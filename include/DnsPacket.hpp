#ifndef __MDNS_DNSPACKET_HPP__
#define __MDNS_DNSPACKET_HPP__

#include <memory>
#include <vector>
#include <string>
#include <list>

namespace MDns {

class DnsPacket {
  
public:
  
    typedef enum {
        RECORDTYPE_IGNORE = 0,
        //Address
        RECORDTYPE_A = 1,
        //Domain Name pointer
        RECORDTYPE_PTR = 12,
        //Arbitrary text string
        RECORDTYPE_TXT = 16,
        //IP6 Address [Thomson]
        RECORDTYPE_AAAA = 28,
        //Server Selection [RFC2782]
        RECORDTYPE_SRV = 33,
        // OPT [RFC 6891]
        RECORDTYPE_OPT = 41,
        //NSEC [RFC 4034]
        RECORDTYPE_NSEC = 47
    } record_type_t ;
    
    typedef enum {
        ENTRYTYPE_ANSWER = 1,
        ENTRYTYPE_AUTHORITY = 2,
        ENTRYTYPE_ADDITIONAL = 3
    } entry_type_t;
    
    typedef enum {
        CLASS_IN = 1,
        CACHE_FLUSH = 0x8000
    } class_type_t;
    
    typedef struct {
        std::string name;
        uint16_t qtype;
        uint16_t qclass;
        bool unicast;
    } Question;
    
    typedef struct {
        std::string name;
        uint16_t rtype;
        uint16_t rclass;
        uint32_t ttl;
        uint16_t length;
        bool     cacheFlush;
        union {
            struct sockaddr_in  a;    // A RECORD
            struct sockaddr_in6 aaaa; // AAAA RECORD
        } data;
    } Record;
    
    typedef struct {
        uint16_t transactionId;
        uint16_t flags;
        uint16_t questionsRRS;
        uint16_t answerRRS;
        uint16_t authorityRRS;
        uint16_t additionalRRS;
        std::list<std::shared_ptr<Question>> questions;
        std::list<std::shared_ptr<Record>>   records;
    } Packet;
     
    static std::shared_ptr<std::vector<uint8_t>> NewQueryA (
        const std::string& name);
    
    static std::shared_ptr<std::vector<uint8_t>> NewResponseA (
        const std::string& name,
        uint32_t ttl,
        struct sockaddr_in *addr);
    
    static std::shared_ptr<std::vector<uint8_t>> NewResponseAAAA (
        const std::string& name,
        uint32_t ttl,
        struct sockaddr_in6 *addr);
    
    static std::shared_ptr<Packet> Parse (
        std::shared_ptr<std::vector<uint8_t>> buffer);

    
private:
  
    static std::shared_ptr<Logger> LOG;
  
    static uint16_t transactionId;
        
    static inline uint16_t getUint16 (
        std::shared_ptr<std::vector<uint8_t>> packet, 
        size_t &cursor);
    
    static inline uint16_t getUint32 (
        std::shared_ptr<std::vector<uint8_t>> packet, 
        size_t &cursor);
    
    static std::string getString (
        std::shared_ptr<std::vector<uint8_t>> buffer, 
        size_t& offset);

    static inline void addUint16 (
        std::shared_ptr<std::vector<uint8_t>> packet, 
        uint16_t value);
    
    static inline void addUint32 (
        std::shared_ptr<std::vector<uint8_t>> packet, 
        uint32_t value);
    
    static void addString (
        std::shared_ptr<std::vector<uint8_t>> packet, 
        const std::string& name);

    static std::shared_ptr<std::string> getLabel (
        std::shared_ptr<std::vector<uint8_t>> buffer, 
        size_t& offset,
        int32_t &pointerReturnAddress);
    
    static bool isStringPointer (
        uint8_t val);
    
    static std::shared_ptr<DnsPacket::Record> parseRecord (
        std::shared_ptr<std::vector<uint8_t>> buffer,
        size_t& offset,
        entry_type_t type);
    
};

}

#endif
