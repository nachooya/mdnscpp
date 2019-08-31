#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include "../third_party/uuid/include/uuid/uuid.hpp"
#include "Client.hpp"

namespace MDns {
  
std::shared_ptr<Logger> Client::LOG = Logger::Get("Client");

void Client::libuvAllocCallback (
    uv_handle_t* handle, 
    size_t suggested_size, 
    uv_buf_t* buf) 
{
    buf->base = (char*) malloc (suggested_size);
    buf->len = suggested_size;
}

void Client::libuvHandleUdpDatagram (
    uv_udp_t* handle, 
    ssize_t nread, 
    const uv_buf_t* buf, 
    const struct sockaddr* addr, 
    unsigned flags) 
{
    LOG->debug ("libuvHandleUdpDatagram: nread: % flags:%, buf->len: %", 
                nread, flags, buf->len);
    auto mdns = (Client*)handle->data;
    auto selfReference = mdns->shared_from_this();
    mdns->handleUdpDatagram (handle, nread, buf, addr, flags);
    LOG->debug ("libuvHandleUdpDatagram: END");
}
  
void Client::handleUdpDatagram (
    uv_udp_t* handle, 
    ssize_t nread, 
    const uv_buf_t* buf, 
    const struct sockaddr* addr, 
    unsigned flags) 
{

    auto selfReference = shared_from_this();
      
    auto mdns = (Client*)handle->data;
  
    if (nread == -1) {
        LOG->debug ("Read error!");
        uv_close((uv_handle_t*) handle, NULL);
    } else if (nread == 0 && addr == nullptr) {
        LOG->debug ("libuvHandleUdpDatagram: nothing to read");
    } else if (nread == 0 && addr != nullptr) {
        LOG->debug ("libuvHandleUdpDatagram: empty datagram");
    } else if (flags == UV_UDP_PARTIAL) {
        LOG->debug ("libuvHandleUdpDatagram: partial UDP datagram");
    } else {
      
        std::string ipaddress;
        
        std::string iface = mdns->_udpHandleToInterface[handle].name;
      
        if (addr->sa_family == AF_INET) {
            char sender[17] = { 0 };
            uv_ip4_name((struct sockaddr_in*) addr, sender, 16);
            ipaddress = sender;
            LOG->debug ("Recv from IPv4 %", sender);
        } else if (addr->sa_family == AF_INET6) {      
            char sender[129] = { 0 };
            uv_ip6_name ((struct sockaddr_in6*) addr, sender, 128);           
            ipaddress = sender;
            LOG->debug ("Recv from IPv6 %", sender);
        }

        LOG->info ("Received packet len: %", nread);
        auto buffer = std::make_shared<std::vector<uint8_t>> ((uint8_t*)buf->base, (uint8_t*)buf->base+nread);
        auto packet = DnsPacket::Parse (buffer);
        
        if (packet) {
          
            for (auto &question: packet->questions) {
                if (question->qtype == DnsPacket::RECORDTYPE_A) {
                    if (question->name == mdns->_uuid) {
                        LOG->info ("Received QUESTION TYPE A to me: % from [% @ %]", question->name, ipaddress, iface);
                        mdns->sendResponseA (handle, DEFAULT_TTL);
                    }   
                } else if (question->qtype == DnsPacket::RECORDTYPE_AAAA) {
                    if (question->name == mdns->_uuid) {
                        LOG->info ("Received QUESTION TYPE AAAA to me: % from [% @ %]", question->name, ipaddress, iface);
                        mdns->sendResponseAAAA (handle, DEFAULT_TTL);
                    }   
                } else {
                    LOG->info ("Received QUESTION TYPE: % name: % - IGNORING IT", question->qtype, question->name);
                }
            }
          
            for (auto &record: packet->records) {
                if (record->rtype == DnsPacket::RECORDTYPE_A) {                                        

                    time_t expirationTime = time(nullptr)+record->ttl;
                    char ipv4address[17] = { 0 };
                    uv_ip4_name (&record->data.a, ipv4address, 16);

                    LOG->info ("Received RECORD TYPE A ttl: %: % => % [CACHE FLUSH: %] from [% @ %]", 
                                   record->ttl,
                                   record->name, ipv4address, record->cacheFlush, ipaddress, iface);
                    
                    if (record->ttl == 0) { // Remove
                        mdns->_recordsA.erase (record->name);
                    } else {                    
                        mdns->_recordsA[record->name] = std::make_pair (expirationTime, std::string(ipv4address));
                        mdns->printCache();
                        mdns->notify (DnsPacket::RECORDTYPE_A, record->name, ipv4address);
                    }            
                    
                } else if (record->rtype == DnsPacket::RECORDTYPE_AAAA) {
                  
                    char ipv6address[129] = { 0 };
                    uv_ip6_name (&record->data.aaaa, ipv6address, 128);
                    time_t expirationTime = time(nullptr)+record->ttl;
                    
                    LOG->info ("Received RECORD TYPE AAAA: % => % [CACHE FLUSH: %] from [% @ %]", record->name, ipv6address, record->cacheFlush, ipaddress, iface);
                    
                    if (record->ttl == 0) { // Remove
                        mdns->_recordsAAAA.erase (record->name);
                    } else {            
                        mdns->_recordsAAAA[record->name] = std::make_pair (expirationTime, std::string(ipv6address));
                        mdns->printCache();
                        mdns->notify (DnsPacket::RECORDTYPE_AAAA, record->name, ipv6address);
                    }                                    
                    
                    
                } else {
                    LOG->info ("Received RECORD TYPE %: name: % - IGNORING IT", record->rtype, record->name);
                }
            }
        }
    }
    
    free (buf->base);
}

std::shared_ptr<Client> Client::New (
    uv_loop_t* loop, 
    NetworkInterfaceFilter filter) 
{
    return std::shared_ptr<Client> (new Client(loop, filter));
}

Client::Client (
    uv_loop_t* loop, 
    NetworkInterfaceFilter filter) 
{
  
    if (loop) {
        _loop = loop;
    } else {
        _loop = uv_default_loop();
    }
    
    _uuid = uuids::system_uuid().to_string()+".local";
    
    LOG->info ("Created with uuid: %", _uuid);
    
    auto ifaces = getNetworkInterfaces (filter);
    for (auto &iface: *ifaces) {
    
        uv_udp_t* uv_udp = nullptr;
      
        if (iface.sa_family == AF_INET6) {
            uv_udp = socketOpenIpv6 (iface.name);
            
        } else if (iface.sa_family == AF_INET) {
            uv_udp = socketOpenIpv4 (iface.name);
        }
          
        if (uv_udp == nullptr) {
            LOG->error ("Error on socketOpen");
            
        } else if (uv_udp_recv_start (uv_udp, libuvAllocCallback, libuvHandleUdpDatagram) != 0) {
            LOG->error ("Error on uv_udp_recv_start");
            
        } else {
          
            _udpHandleToInterface[uv_udp] = iface;
            
            if (iface.sa_family == AF_INET6) {
                _ifaceToUdpHandleIpv6[iface.name] = uv_udp;
            } else if (iface.sa_family == AF_INET) {
                _ifaceToUdpHandleIpv4[iface.name] = uv_udp;
            }
            
            LOG->info ("* Open iface: % type: % socket: % addr: % ", 
                           iface.name, 
                           iface.sa_family==AF_INET?"IPv4":"IPv6",
                           socket,
                           iface.ipAddress);
        }        
    }
}

Client::~Client() {
  
    LOG->debug ("Mdns: Destructor");

    // Send TTL 0 for A record.
    announceA (0);
    
    for (auto &uv_udp: _udpHandleToInterface) {
      
        if (uv_udp_recv_stop (uv_udp.first) != 0) {
            LOG->error ("Error on uv_udp_recv_stop");
        }
        
        uv_close((uv_handle_t*) uv_udp.first, [](uv_handle_t* handle) {
            LOG->debug ("libuvCloseCallback");
            delete handle;
        });
    }
    
}

void Client::notify (
    DnsPacket::record_type_t type, 
    const std::string& name, 
    const std::string& ipv4) 
{
  
    LOG->debug ("notify type: %", type);
    auto selfReference = shared_from_this();
    
    recordCallbacks_t& callbacks = _recordsACallbacks;
    
    if (type == DnsPacket::RECORDTYPE_A) {
        callbacks = _recordsACallbacks;
    } else if (type == DnsPacket::RECORDTYPE_AAAA) {
        callbacks = _recordsAAAACallbacks;
    }
    
    auto it = callbacks.find (name);
    if (it != callbacks.end()) {
      
        auto itQueries = it->second.begin();
        
        while (itQueries != it->second.end()) {
            auto queryHandler = *itQueries;          
            // Remove the timer                    
            uv_timer_stop (queryHandler->uvTimerHandler.get());
            auto uvTimerHandler = queryHandler->uvTimerHandler.release();
            uv_close ((uv_handle_t *)uvTimerHandler, [](uv_handle_t* handle) {
                delete handle;
            });
            
            if (!queryHandler->callbackWeak.expired()) {
                (*queryHandler->callbackWeak.lock()) (false, name, ipv4);
            }
            itQueries++;
        }
        callbacks.erase (it);
    }
}

std::string Client::getLocalDomain() 
{
    return _uuid;
}

void Client::libuvTimeoutHandlerForQueries (
    uv_timer_t* handle) 
{

    auto queryHandler = (queryHandler_t*) handle->data;
    
    LOG->debug ("libuvTimeoutHandlerForQueries name: %", queryHandler->name);
    
    auto mdns = queryHandler->mdns;
    
    auto selfReference = mdns->shared_from_this();
        
    auto uvTimerHandler = queryHandler->uvTimerHandler.release();
    uv_close ((uv_handle_t *)uvTimerHandler, [](uv_handle_t* handle) {
        delete handle;
    });
    
    if (!queryHandler->callbackWeak.expired()) {
        (*queryHandler->callbackWeak.lock()) (true, queryHandler->name, "");
    }
    
    auto it = mdns->_recordsACallbacks.find (queryHandler->name);
    if (it != mdns->_recordsACallbacks.end()) {
        auto list = it->second;        
        std::remove_if (std::begin (list),
                        std::end   (list),
                        [&]( std::shared_ptr<queryHandler_t> q ){ return queryHandler == q.get(); } );
    }
    
    LOG->debug ("libuvTimeoutHandlerForQueries END");
    
}

void Client::queryA (
    const std::string& name, 
    std::shared_ptr<CallbackA> 
    callback, 
    uint32_t timeoutMsecs) 
{
    LOG->info ("query TYPE_A to: %", name);
    
    //First check cache and TTL
    auto it = _recordsA.find(name);
    if (it != _recordsA.end()) {
        // Check ttl
        time_t expirationTime = it->second.first;
        if (expirationTime < time(nullptr)) {
            return (*callback) (false, name, it->second.second);
        } else {
            _recordsA.erase(it);
        }
    }
    
    // Not found or expired do query
  
    std::weak_ptr<CallbackA> callbackWeak = callback;            
    auto queryHandler = std::make_shared<queryHandler_t>();
    queryHandler->mdns = this;
    queryHandler->callbackWeak = callbackWeak;            
    queryHandler->name = name;
    queryHandler->timeoutMsecs = timeoutMsecs;
    
    _recordsACallbacks[name].push_back (queryHandler);
 
    auto packet = DnsPacket::NewQueryA (queryHandler->name);
    
    for (auto &uv_udp: queryHandler->mdns->_udpHandleToInterface) {
        sendPacket (uv_udp.first, packet);        
    }
    
    // Set timeout    
    uv_timer_init (_loop, queryHandler->uvTimerHandler.get());
    queryHandler->uvTimerHandler->data = queryHandler.get();
    uv_timer_start (queryHandler->uvTimerHandler.get(), libuvTimeoutHandlerForQueries, queryHandler->timeoutMsecs, 0);
    
}

std::shared_ptr<std::list<Client::networkInterface_t>> Client::getNetworkInterfaces (
    NetworkInterfaceFilter filter) 
{

    LOG->debug ("getNetworkInterfaces: filter: %", filter);
  
    auto result = std::make_shared<std::list<Client::networkInterface_t>>();
  
    struct ifaddrs *addrs, *cursor;
    getifaddrs (&addrs);
    cursor = addrs;
    
    while (cursor) {
        if (cursor->ifa_addr
            && (cursor->ifa_addr->sa_family == AF_INET || cursor->ifa_addr->sa_family == AF_INET6)
            && (cursor->ifa_flags & IFF_MULTICAST)) 
        {
        
            if ((cursor->ifa_flags & IFF_LOOPBACK) && !(filter & NET_IFACES_LOOPBACK)) {
                cursor = cursor->ifa_next;
                continue;
            } 
            
            if ((cursor->ifa_flags & IFF_POINTOPOINT) && !(filter & NET_IFACES_POINTOPOINT)) {
                cursor = cursor->ifa_next;
                continue;
            }

            if (cursor->ifa_addr->sa_family == AF_INET6) {
                char ipaddr[129] = { 0 };
                if (uv_ip6_name ((const struct sockaddr_in6*) cursor->ifa_addr, ipaddr, 128) != 0) {
                    LOG->error ("getNetworkInterfaces: error on uv_ip6_name");
                } else {
                    result->push_back({
                        cursor->ifa_name,
                        cursor->ifa_addr->sa_family,           
                        std::string (ipaddr)                   
                    });
                }
            } else if (cursor->ifa_addr->sa_family == AF_INET) {
                char ipaddr[17] = { 0 };
                if (uv_ip4_name((const struct sockaddr_in*) cursor->ifa_addr, ipaddr, 16) != 0){
                    LOG->error ("getNetworkInterfaces: error on uv_ip6_name");
                } else {
                    result->push_back({
                        cursor->ifa_name,
                        cursor->ifa_addr->sa_family,           
                        std::string (ipaddr)
                    });
                }
            }
        }
        cursor = cursor->ifa_next;
    }

    freeifaddrs (addrs);
    
    return result;
  
}

uv_udp_t* Client::socketOpenIpv4 (
    const std::string& ifname) 
{

    struct sockaddr_in saddr;
    memset (&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(5353);
#ifdef __APPLE__
    saddr.sin_len = sizeof(saddr);
#endif
  
    uv_udp_t* uv_udp = new uv_udp_t();    
    uv_udp->data = this;
        
    if (uv_udp_init (_loop, uv_udp) != 0) {
        LOG->error ("socketOpenIpv4: error on uv_udp_init");
        delete uv_udp;
        uv_udp = nullptr;
        
    } else if (uv_udp_bind (uv_udp, (const struct sockaddr *)&saddr, UV_UDP_REUSEADDR) != 0) {
        LOG->error ("socketOpenIpv4: error on uv_udp_bind");
        delete uv_udp;
        uv_udp = nullptr;
        
    } else if (uv_udp_set_broadcast (uv_udp, 1) != 0) {
        LOG->error ("socketOpenIpv4: error on  uv_udp_set_broadcast");
        delete uv_udp;
        uv_udp = nullptr;
        
    } else if (uv_udp_set_multicast_loop (uv_udp, 1) != 0) {
        LOG->error ("socketOpenIpv4: error on uv_udp_set_multicast_loop");
        delete uv_udp;
        uv_udp = nullptr;
        
    } else if (uv_udp_set_multicast_ttl (uv_udp, 1) != 0) {
        LOG->error ("socketOpenIpv4: error on uv_udp_set_multicast_ttl");
        delete uv_udp;
        uv_udp = nullptr;
        
    } else if (uv_udp_set_membership (uv_udp, "224.0.0.251", nullptr, UV_JOIN_GROUP) != 0) {
        LOG->error ("socketOpenIpv4: error on uv_udp_set_membership");
        delete uv_udp;
        uv_udp = nullptr;
    }

    return uv_udp;
}

uv_udp_t* Client::socketOpenIpv6 (
    const std::string& ifname) 
{

    struct sockaddr_in6 saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin6_family = AF_INET6;
    saddr.sin6_addr = in6addr_any;
    saddr.sin6_port = htons(5353);
#ifdef __APPLE__
    saddr.sin6_len = sizeof(saddr);
#endif
  
    int ifaceIndex = if_nametoindex (ifname.c_str());
    // JOIN MEMBERSHIP
    struct ipv6_mreq group;
    group.ipv6mr_interface = ifaceIndex;
    inet_pton(AF_INET6, "ff02::fb", &group.ipv6mr_multiaddr);
    
    uv_udp_t* uv_udp = new uv_udp_t();    
    uv_udp->data = this;
        
    if (uv_udp_init (_loop, uv_udp) != 0) {
        LOG->error ("socketOpenIpv6: error on uv_udp_init");
        delete uv_udp;
        uv_udp = nullptr;
        
    } else if (uv_udp_bind (uv_udp, (const struct sockaddr *)&saddr, UV_UDP_REUSEADDR) != 0) {
        LOG->error ("socketOpenIpv6: error on uv_udp_bind");
        delete uv_udp;
        uv_udp = nullptr;
        
//     } else if (int err = uv_udp_set_multicast_interface (uv_udp, nullptr) != 0) {
//         LOG->error ("socketOpenIpv6: error on uv_udp_set_multicast_interface: % err: % % %", ipAddress, err, uv_strerror(err), errno);
//         delete uv_udp;
//         uv_udp = nullptr;
        
    } else if (setsockopt (uv_udp->io_watcher.fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifaceIndex, sizeof(ifaceIndex)) != 0) {
        LOG->error ("Failed to set socket option IPV6_MULTICAST_IF with code %", errno);
        delete uv_udp;
        uv_udp = nullptr; 
        
    } else if (uv_udp_set_broadcast (uv_udp, 1) != 0) {
        LOG->error ("socketOpenIpv6: error on uv_udp_set_broadcast");
        delete uv_udp;
        uv_udp = nullptr;
        
    } else if (uv_udp_set_multicast_loop (uv_udp, 1) != 0) {
        LOG->error ("socketOpenIpv6: error on uv_udp_set_multicast_loop");
        delete uv_udp;
        uv_udp = nullptr;
        
    } else if (uv_udp_set_multicast_ttl (uv_udp, 1) != 0) { // IPV6_MULTICAST_HOPS
        LOG->error ("socketOpenIpv6: error on uv_udp_set_multicast_ttl");
        delete uv_udp;
        uv_udp = nullptr;
        
//     } else if (uv_udp_set_membership (uv_udp, "ff02::fb", nullptr, UV_JOIN_GROUP) != 0) {
//         LOG->error ("socketOpenIpv6: error on uv_udp_set_membership");
//         delete uv_udp;
//         uv_udp = nullptr;
//     }
    
    } else if (setsockopt (uv_udp->io_watcher.fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &group, sizeof group) != 0) {
        LOG->error("Failed to set socket option IPV6_JOIN_GROUP with code %", errno);
        delete uv_udp;
        uv_udp = nullptr;
    }

    return uv_udp;
}

int Client::sendPacket (
    uv_udp_t* uv_udp, 
    std::shared_ptr<std::vector<uint8_t>> packet) 
{
  
    struct sockaddr_storage addr_storage;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;
    struct sockaddr* saddr = (struct sockaddr*)&addr_storage;
    int saddrlen = sizeof(struct sockaddr_storage);
    
    if (uv_udp_getsockname (uv_udp, saddr, &saddrlen) != 0) {
        LOG->error ("sendPacket: error on uv_udp_getsockname");
        return -1;
    }
    
    if (saddr->sa_family == AF_INET6) {
        memset (&addr6, 0, sizeof(struct sockaddr_in6));
        addr6.sin6_family = AF_INET6;
#ifdef __APPLE__
        addr6.sin6_len = sizeof(struct sockaddr_in6);
#endif
        addr6.sin6_addr.s6_addr[0] = 0xFF;
        addr6.sin6_addr.s6_addr[1] = 0x02;
        addr6.sin6_addr.s6_addr[15] = 0xFB;
        addr6.sin6_port = htons((unsigned short)5353);
        saddr = (struct sockaddr*)&addr6;
        saddrlen = sizeof(struct sockaddr_in6);
    } else if (saddr->sa_family == AF_INET) {
        memset(&addr, 0, sizeof(struct sockaddr_in));
        addr.sin_family = AF_INET;
#ifdef __APPLE__
        addr.sin_len = sizeof(struct sockaddr_in);
#endif
        addr.sin_addr.s_addr = htonl((((uint32_t)224U) << 24U) | ((uint32_t)251U));
        addr.sin_port = htons((unsigned short)5353);
        saddr = (struct sockaddr*)&addr;
        saddrlen = sizeof(struct sockaddr_in);
    }
    
    LOG->debug ("sendPacket: size: %lu", packet->size());
    
    uv_buf_t buf;
    buf.base = reinterpret_cast<char*>(packet->data());
    buf.len = packet->size(); 
    
    if (uv_udp_try_send (uv_udp, &buf, 1, saddr) <= 0) {
        LOG->error ("sendPacket: error no uv_udp_try_send");
        return -1;
    } else {
        return 0;
    }
}

void Client::announceA (
    uint32_t ttl) 
{  
    for (auto& udpHandle : _udpHandleToInterface) {
        sendResponseA (udpHandle.first, ttl);
    }
  
}

void Client::announceAAAA (
    uint32_t ttl) 
{
    for (auto& udpHandle : _udpHandleToInterface) {
        sendResponseAAAA (udpHandle.first, ttl);
    }
}

void Client::sendResponseA (
    uv_udp_t* handleFrom, 
    uint32_t ttl) 
{
  
    //NOTE: Query could be received on IPv4 but must be announce to
    // IPv6 as well
  
    auto itIface = _udpHandleToInterface.find (handleFrom);
    if (itIface != _udpHandleToInterface.end()) {
        auto ifaceName = itIface->second.name;
        auto it = _ifaceToUdpHandleIpv4.find (ifaceName);  
        if (it != _ifaceToUdpHandleIpv4.end()) {
          
            uv_udp_t* handleTo = it->second;
            auto itIPv4Iface = _udpHandleToInterface.find (handleTo);
            if (itIPv4Iface != _udpHandleToInterface.end()) {
          
                struct sockaddr_in saddr;                              
                if (uv_ip4_addr (itIPv4Iface->second.ipAddress.c_str(), 0, &saddr) == 0) {
                
                    auto response = DnsPacket::NewResponseA (_uuid,
                                                              ttl,
                                                              &saddr);
                    
                    LOG->info ("Send RECORD TYPE A with TTL [%] via [%: %]", ttl, ifaceName, itIface->second.ipAddress);
                    sendPacket (handleFrom, response);
                } else {
                    LOG->error ("sendResponseA: error on uv_ip4_addr with ip address: %", itIPv4Iface->second.ipAddress);
                }                
            }
        }
    }
}

void Client::sendResponseAAAA (
    uv_udp_t* handleFrom, 
    uint32_t ttl) 
{
  
    //NOTE: Query could be received on IPv6 but must be announce to
    // IPv4 as well
  
    auto itIface = _udpHandleToInterface.find (handleFrom);
    if (itIface != _udpHandleToInterface.end()) {
        auto ifaceName = itIface->second.name;
        auto it = _ifaceToUdpHandleIpv6.find (ifaceName);  
        if (it != _ifaceToUdpHandleIpv6.end()) {
          
            uv_udp_t* handleTo = it->second;
            auto itIPv6Iface = _udpHandleToInterface.find (handleTo);
            if (itIPv6Iface != _udpHandleToInterface.end()) {
          
                struct sockaddr_in6 saddr;                              
                if (uv_ip6_addr (itIPv6Iface->second.ipAddress.c_str(), 0, &saddr) == 0) {
                
                    auto response = DnsPacket::NewResponseAAAA (_uuid,
                                                                 ttl,
                                                                 &saddr);
                    
                    LOG->info ("Send RECORD TYPE A with TTL [%] via [%: %]", ttl, ifaceName, itIface->second.ipAddress);
                    sendPacket (handleFrom, response);
                } else {
                    LOG->error ("sendResponseA: error on uv_ip4_addr with ip address: %", itIPv6Iface->second.ipAddress);
                }                
            }
        }
    }
}

void Client::printCache () {
    
    auto now = time (NULL);
        
    LOG->info ("==============================================================================");
    LOG->info ("|                                IPv4                                        |");
    LOG->info ("------------------------------------------------------------------------------");
    LOG->info ("|  name                                      | address       | TTL (seconds) |");
    LOG->info ("------------------------------------------------------------------------------");
    for (auto& record: _recordsA) {
        auto name    = record.first;
        auto ttl     = record.second.first;
        auto address = record.second.second;
        LOG->info ("| % | % |           % |", name, address, ttl-now);
    }
    LOG->info ("------------------------------------------------------------------------------");
    LOG->info ("|                                IPv6                                        |");
    LOG->info ("------------------------------------------------------------------------------");
    for (auto& record: _recordsAAAA) {
        auto name    = record.first;
        auto ttl     = record.second.first;
        auto address = record.second.second;
        LOG->info ("| % | % |           % |", name, address, ttl-now);
    }
    LOG->info ("==============================================================================");
}

}
