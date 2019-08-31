#include <unistd.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include <uv.h>
#include <Logger.hpp>
#include <Client.hpp>

namespace MDns {

class NhLookup {
  
public:
  
    NhLookup() {
      
        Logger::setLogLevel (Logger::ERROR);
  
        mdnsCallback = std::make_shared<MDns::Client::CallbackA> ([&](bool error, const std::string& name, const std::string& ipAddress) {
            if (error) {
                printf ("\n>> Host with name: %s not found. Timeout (%u ms).\n", name.c_str(), queryTimeoutMsecs);
            } else {
                printf ("\n>> %s => %s\n", name.c_str(), ipAddress.c_str());
            }
            std::cout << "> " << std::flush;
        });
        
        mdns = MDns::Client::New (uv_default_loop(), ifacefilter);
        
        std::cout << std::endl;
        std::cout << "Host Multicast DNS UUID: " << mdns->getLocalDomain() << std::endl;
        std::cout << std::endl;
        std::cout << "Enter h or ? for help" << std::endl;
        std::cout << "> " << std::flush;        
               
    }
    
    void start () {
        setUpTty();
        
        if (uv_run (uv_default_loop(), UV_RUN_DEFAULT) != 0) {
            std::cerr << "Error on uv_run\n";
        } else if (uv_loop_close (uv_default_loop()) != 0) {
            std::cerr << "Error on uv_loop_close\n";
        } else {
            std::cout << std::endl << std::flush;            
        }   
    }
  
private:
    
    std::shared_ptr<Client> mdns = nullptr;
    std::shared_ptr<Client::CallbackA> mdnsCallback = nullptr;
    uv_tty_t              ttyIn;
    std::stringstream     stdinStream;  
    uint32_t              queryTimeoutMsecs = 500;
    MDns::Client::NetworkInterfaceFilter ifacefilter = MDns::Client::NET_IFACES_DEFAULT;

    void setUpTty () {
        if (uv_tty_init (uv_default_loop(), &ttyIn, STDIN_FILENO, 1) != 0) {
           std::cerr << "Error on uv_ttyInit";
        } else {
            ttyIn.data = this;
            if (uv_read_start((uv_stream_t*)&ttyIn, libuvTtyAlloc, libuvTtyRead) != 0) {
                std::cerr << "Error on uv_read_start";
            }
        }
    }
    
    void printHelp() {
      
        std::cout 
        << "======= nhlookup HELP =======" << std::endl
        << " Available commands:" << std::endl
        << "    * q: Quits nhlookup" << std::endl
        << "    * h: prints this Help" << std::endl
        << "    * c: show nhlookup A records Cache" << std::endl
        << "    * r: prints nhlookup device A Record" << std::endl
        << "    * i: prints network Intefaces being used by nhlookup" << std::endl
        << "    * l level: change Log level" << std::endl
        << "         Available levels are:" << std::endl
        << "            0: NONE" << std::endl
        << "            1: ERROR" << std::endl
        << "            2: WARN" << std::endl
        << "            3: INFO" << std::endl
        << "            4: DEBUG" << std::endl
        << "         Example: l 4" << std::endl
        << "    * n: ANNounce: send own A record on all interfaces (TTL=120)" << std::endl
        << "    * m: ANNounce: send own AAAA record on all interfaces (TTL=120)" << std::endl
        << "    * d: Deannounce: send own A record on all interfaces (TTL=0)" << std::endl
        << "    * a record: query A record" << std::endl
        << "         Example: a " << mdns->getLocalDomain() << std::endl
        << "=============================" << std::endl;
      
    }

    void printLocalARecord() {
        std::cout << ">> Host Multicast DNS UUID: " << mdns->getLocalDomain() << std::endl;
    }
    
    void printCachedRecords() {
        
        auto now = time (NULL);
        
        std::cout 
        << ">> ==============================================================================" << std::endl
        << ">> |                                IPv4                                        |" << std::endl
        << ">> ------------------------------------------------------------------------------" << std::endl
        << ">> |  name                                      | address       | TTL (seconds) |" << std::endl
        << ">> ------------------------------------------------------------------------------" << std::endl;
        for (auto& record: mdns->_recordsA) {
            auto name    = record.first;
            auto ttl     = record.second.first;
            auto address = record.second.second;
            std::cout << ">> | "<< name <<" | "<< address <<" |           "<< (ttl-now) <<" |" << std::endl;
        }
        std::cout 
        << ">> ------------------------------------------------------------------------------" << std::endl
        << ">> |                                IPv6                                        |" << std::endl
        << ">> ------------------------------------------------------------------------------" << std::endl;
        for (auto& record: mdns->_recordsAAAA) {
            auto name    = record.first;
            auto ttl     = record.second.first;
            auto address = record.second.second;
            std::cout << ">> | "<< name <<" | "<< address <<" |           "<< (ttl-now) <<" |" << std::endl;
        }
        std::cout
        << ">> ==============================================================================" << std::endl;
    }
    
    void printNetworkInterfaces() {
       auto ifaces = mdns->getNetworkInterfaces(ifacefilter);
       std::cout << ">> Got " << ifaces->size() << " interfaces" << std::endl;
       for (auto &iface: *ifaces) {
          std::cout << ">> * " << iface.name << " : "  
          << (iface.sa_family==AF_INET?"IPv4: ":"IPv6: ")
          << iface.ipAddress
          << std::endl;
       }
    }

    void changeLogLevel (std::string level) {
        
        try {
            auto l = (Logger::LOG_LEVEL) std::stoi(level);
            std::cout << ">> New Log Level " << l << std::endl;
            Logger::setLogLevel (l);
        } catch (...) {
            std::cout << ">> Invalid Log Level: " << level;
        };
    
    }

    void parseCommand (const std::string& line) {
        if (line.empty()) {
            
        } else if (line == "h" || line == "?" || line == "help") {       
            printHelp ();
            
        } else if (line == "r") {
            printLocalARecord();
            
        } else if (line == "i") {
            printNetworkInterfaces();
            
        } else if (line.at(0) == 'l') {
            if (line.size() <= 2) {
                std::cout << ">> Wrong sintax for l command" << std::endl;
            } else {
                std::string level = line.substr(2);
                changeLogLevel (level);        
            }
            
        } else if (line == "q") {
          
            std::cout << "QUITING..." << std::endl << std::flush;
          
            mdns = nullptr;
            if (uv_read_stop((uv_stream_t*)&ttyIn) != 0) {
                printf ("Error on uv_read_stop");
            } else {
                uv_close((uv_handle_t*) &ttyIn, NULL);
            }
            
        } else if (line == "c") {
            printCachedRecords();
            
        } else if (line == "n") {
            mdns->announceA();
        
        } else if (line == "m") {
            mdns->announceAAAA();
            
        } else if (line == "d") {
            mdns->announceA(0);
            
        } else if (line.at(0) == 'a') {
            if (line.size() <= 2) {
                std::cout << ">> Wrong sintax for a command" << std::endl;
            } else { 
                std::string record = line.substr(2);
                mdns->queryA (record, mdnsCallback, queryTimeoutMsecs);
            }
            
        } else {
            std::cout << ">> Unknown command: enter h for help" << std::endl;
            
        }
        std::cout << "> " << std::flush;
    }

    static void libuvTtyAlloc (uv_handle_t* handle, size_t size, uv_buf_t* buf) {
        buf->base = (char*) malloc (size);
        buf->len = size;
    }

    static void libuvTtyRead (uv_stream_t* ttyIn, ssize_t nread, const uv_buf_t* buf) {
      
        auto nhlookup = (NhLookup*) ttyIn->data;
      
        if (nread > 0) {
            nhlookup->stdinStream.write (buf->base, nread);
            std::string line;
            std::getline (nhlookup->stdinStream, line);
            nhlookup->parseCommand (line);
        } else {
            
        }
        
        free (buf->base);
    }
    
};

}

int main (int argc, char* argv[]) {
  
    auto nhlookup = new MDns::NhLookup ();
    nhlookup->start();
    delete nhlookup;
    return 0;
}
