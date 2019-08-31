#ifndef __MDNS_CLIENT_HPP__
#define __MDNS_CLIENT_HPP__

#include <functional>
#include <list>
#include <map>
#include <utility>
#include <time.h>
#include <uv.h>
#include "Logger.hpp"
#include "DnsPacket.hpp"

namespace MDns {

class Client: public std::enable_shared_from_this<Client> {
  
public:
  
    typedef enum {
        NET_IFACES_LOOPBACK    = 0x01, // 0000 0001
        NET_IFACES_POINTOPOINT = 0x02, // 0000 0010
        NET_IFACES_DEFAULT     = 0x04, // 0000 0100
        NET_IFACES_ALL         = 0x07, // 0000 0111
    } NetworkInterfaceFilter;
       
    typedef std::function<void(
        bool error, 
        const std::string& name, 
        const std::string& ipAddress
    )> CallbackA;
  
    static std::shared_ptr<Client> New (
        uv_loop_t* loop, 
        NetworkInterfaceFilter filter = NET_IFACES_DEFAULT);
    
    ~Client (); 
    
    std::string getLocalDomain();
    
    void announceA (
        uint32_t ttl = DEFAULT_TTL);
    
    void announceAAAA (
        uint32_t ttl = DEFAULT_TTL);
    
    void queryA (
        const std::string& name, 
        std::shared_ptr<CallbackA> callback, 
        uint32_t timeoutMsecs);
    
private:

    friend class NhLookup;
    
    typedef struct {
        std::string name;
        uint32_t    sa_family;
        std::string ipAddress;
    } networkInterface_t;
    
    typedef struct {
        Client* mdns;
        std::weak_ptr<CallbackA> callbackWeak;
        std::unique_ptr<uv_timer_t> uvTimerHandler = std::make_unique<uv_timer_t>();
        std::string name;
        uint32_t timeoutMsecs;
    } queryHandler_t;
    
    static const int32_t DEFAULT_TTL = 120;
    static std::shared_ptr<Logger> LOG;

    //NOTE: recordName -> list of query Handlers 
    typedef std::map<
        std::string, 
        std::list<std::shared_ptr<queryHandler_t>>
    > recordCallbacks_t;
    
    uv_loop_t* _loop = nullptr;
    
    std::string _uuid;
    std::map<uv_udp_t*, networkInterface_t> _udpHandleToInterface;
    std::map<std::string, uv_udp_t*>        _ifaceToUdpHandleIpv4;
    std::map<std::string, uv_udp_t*>        _ifaceToUdpHandleIpv6;

    //NOTE: value is <expiration(ttl), IPv4>
    std::map<std::string, std::pair<time_t, std::string>> _recordsA; 
    recordCallbacks_t _recordsACallbacks;
    
    //NOTE: value is <expiration(ttl), IPv6>
    std::map<std::string, std::pair<time_t, std::string>> _recordsAAAA; 
    recordCallbacks_t _recordsAAAACallbacks;
       
    Client (
        uv_loop_t* loop, 
        NetworkInterfaceFilter filter);
    
    static void libuvAllocCallback (
        uv_handle_t* handle, 
        size_t suggested_size, 
        uv_buf_t* buf);
    
    static void libuvHandleUdpDatagram (
        uv_udp_t* handle, ssize_t nread, 
        const uv_buf_t* buf, 
        const struct sockaddr* addr, 
        unsigned flags);
    
    static void libuvTimeoutHandlerForQueries (
        uv_timer_t* handle);    
        
    std::shared_ptr<std::list<networkInterface_t>> getNetworkInterfaces (
        NetworkInterfaceFilter filter);
    
    void handleUdpDatagram (
        uv_udp_t* handle, 
        ssize_t nread, 
        const uv_buf_t* buf, 
        const struct sockaddr* addr,
        unsigned flags);
    
    uv_udp_t* socketOpenIpv4 (
        const std::string& ifname);
    
    uv_udp_t* socketOpenIpv6 (
        const std::string& ifname);
    
    void notify (
        DnsPacket::record_type_t type, 
        const std::string& name, const 
        std::string& ipv4);
    
    int sendPacket (
        uv_udp_t* uv_udp, 
        std::shared_ptr<std::vector<uint8_t>> packet);
    
    void sendResponseA (
        uv_udp_t* handleFrom, 
        uint32_t ttl);
    
    void sendResponseAAAA (
        uv_udp_t* handleFrom,
        uint32_t ttl);

    void printCache ();

};

}

#endif
