#include <cstring>
#include <arpa/inet.h>
#include "Logger.hpp"
#include "DnsPacket.hpp"

namespace MDns {

std::shared_ptr<Logger> DnsPacket::LOG = Logger::Get("DnsPacket");

uint16_t DnsPacket::transactionId = 0x0000U;

std::shared_ptr<std::vector<uint8_t>> DnsPacket::NewQueryA (
  const std::string& name) 
{
      
    auto packet = std::make_shared<std::vector<uint8_t>> ();
    packet->reserve(100);
    
    //Transaction ID
    addUint16 (packet, htons(transactionId));
    //Flags
    addUint16 (packet, htons(0));
    //Questions
    addUint16 (packet, htons(1));
    //No answer, authority or additional RRs
    addUint16 (packet, htons(0));
    addUint16 (packet, htons(0));
    addUint16 (packet, htons(0));
    //Name string
    addString (packet, name);
    //Record type
    addUint16 (packet, htons(RECORDTYPE_A));
    //! Unicast response, class IN
    //*data++ = htons(0x8000U | CLASS_IN);
    //! Multicast response, class IN
    addUint16 (packet, htons(0x0000U | CLASS_IN));
    
    return packet;

}

std::shared_ptr<std::vector<uint8_t>> DnsPacket::NewResponseA (
    const std::string& name,
    uint32_t ttl,
    struct sockaddr_in *addr)
{
  
    auto packet = std::make_shared<std::vector<uint8_t>> ();
    packet->reserve(100);

    // Transaction ID
    addUint16 (packet, htons(transactionId));
    // Flags
    addUint16 (packet, htons(0x8400)); // Standard Query response, no error;
    // Questions
    addUint16 (packet, htons(0));
    // Answer RRs
    addUint16 (packet, htons(1));
    // Authority RRs
    addUint16 (packet, htons(0));
    // Additional RRs
    addUint16 (packet, htons(0));
    // Name string
    addString (packet, name);
    // Record type
    addUint16 (packet, htons(RECORDTYPE_A));
    // CacheFlush, Class IN, 
    addUint16 (packet, htons(0x8000U | CLASS_IN));
    // TTL 120 seconds
    addUint32 (packet, htonl(ttl));
    // Data lenght 4
    addUint16 (packet, htons(0x04));
    // IPv4 Address
    for (int i = 0; i < 4; i++) {
        packet->push_back (((uint8_t*)&addr->sin_addr.s_addr)[i]);
    }   
        
    return packet;
}

std::shared_ptr<std::vector<uint8_t>> DnsPacket::NewResponseAAAA (
    const std::string& name,
    uint32_t ttl,
    struct sockaddr_in6 *addr)
{
  
    auto packet = std::make_shared<std::vector<uint8_t>> ();
    packet->reserve(100);

    // Transaction ID
    addUint16 (packet, htons(transactionId));
    // Flags
    addUint16 (packet, htons(0x8400)); // Standard Query response, no error;
    // Questions
    addUint16 (packet, htons(0));
    // Answer RRs
    addUint16 (packet, htons(1));
    // Authority RRs
    addUint16 (packet, htons(0));
    // Additional RRs
    addUint16 (packet, htons(0));
    // Name string
    addString (packet, name);
    // Record type
    addUint16 (packet, htons(RECORDTYPE_AAAA));
    // CacheFlush, Class IN, 
    addUint16 (packet, htons(0x8000U | CLASS_IN));
    // TTL 120 seconds
    addUint32 (packet, htonl(ttl));
    // Data lenght 16
    addUint16 (packet, htons(0x10));
    // IPv6 Address
    for (int i = 0; i < 16; i++) {
        packet->push_back (((uint8_t*)&addr->sin6_addr)[i]);
    }   
        
    return packet;
}

inline void DnsPacket::addUint16 (
    std::shared_ptr<std::vector<uint8_t>> packet, 
    uint16_t value) 
{
    packet->push_back ((uint8_t)(value & 0x00FF));        // LOW byte
    packet->push_back ((uint8_t)((value & 0xFF00) >> 8)); // HIGH byte
}

inline void DnsPacket::addUint32 (
    std::shared_ptr<std::vector<uint8_t>> packet, 
    uint32_t value) 
{
    packet->push_back ((uint8_t)((value & 0x000000FF)));     
    packet->push_back ((uint8_t)((value & 0x0000FF00) >> 8));
    packet->push_back ((uint8_t)((value & 0x00FF0000) >> 16));
    packet->push_back ((uint8_t)((value & 0xFF000000) >> 24));
}

inline uint16_t DnsPacket::getUint16 (
    std::shared_ptr<std::vector<uint8_t>> packet, 
    size_t &cursor) 
{
    int val = 0;
    if (cursor+1 >= packet->size()) {
        LOG->error ("getUint16: Error packet->size: % cursor: %", 
                    packet->size(), 
                    cursor);
    } else {
        uint8_t lowByte  = packet->at (cursor++);
        uint8_t highByte = packet->at (cursor++);
        val = highByte;
        val = val << 8;
        val |= lowByte;
    }
    return val;
}

inline uint16_t DnsPacket::getUint32 (
    std::shared_ptr<std::vector<uint8_t>> packet, 
    size_t &cursor) 
{
    uint32_t val = 0;
    if (cursor >= packet->size()) {
        LOG->error ("getUint16: Error packet->size: % cursor: %", 
                    packet->size(), 
                    cursor);
    } else {
        val = packet->at(cursor);
        val = val << 8;
        val = val | packet->at(cursor+1);
        val = val << 8;
        val = val | packet->at(cursor+2);
        val = val << 8;
        val = val | packet->at(cursor+3);
        cursor = cursor + sizeof(val);
    }
    return val;
}

void DnsPacket::addString (
    std::shared_ptr<std::vector<uint8_t>> packet, 
    const std::string& name) 
{
    size_t pos = 0;
    size_t last_pos = 0;
    
    while ((last_pos < name.size()) && 
           ((pos = name.find_first_of (".", last_pos)) != std::string::npos)) 
    {
        size_t sublength = pos - last_pos;
        packet->push_back((uint8_t)sublength);
        std::copy (name.begin()+last_pos, 
                   name.begin()+last_pos+sublength, 
                   std::back_inserter(*packet));
        last_pos = pos + 1;
    }
    if (last_pos < name.size()) {
        size_t sublength = name.size() - last_pos;
        packet->push_back ((uint8_t)sublength);
        std::copy (name.begin()+last_pos, 
                   name.begin()+last_pos+sublength,
                   std::back_inserter(*packet));
    }
    packet->push_back(0x00);
}

bool DnsPacket::isStringPointer (
    uint8_t val) 
{
    auto res = (0xC0 == (val & 0xC0));
    return res;
}

std::shared_ptr<std::string> DnsPacket::getLabel (
    std::shared_ptr<std::vector<uint8_t>> buffer, 
    size_t& offset,
    int32_t &pointerReturnAddress)
{
     
    std::shared_ptr<std::string> result = nullptr;
        
    if (offset >= buffer->size()) {
        // ERROR
        LOG->error ("getLabel: error 1");
    } else if (!buffer->at(offset)) {       
        // END
        LOG->debug ("getLabel: end");
    } else {
        
        if (isStringPointer (buffer->at(offset))) {
                             
            if (buffer->size() < offset + 2) {
                // ERROR
                LOG->error ("getLabel: error 2");
            } else {

                size_t stringPointerStart = 
                    ((((size_t)(0x3f & buffer->at(offset))) << 8) |
                    (size_t)buffer->at(offset + 1));
                
                LOG->debug ("getLabel: pointer to %", stringPointerStart);
                if (stringPointerStart >= buffer->size()) {
                    // ERROR
                    LOG->error ("getLabel: error 3");
                } else {                                                
                    size_t stringLength = (size_t)buffer->at(stringPointerStart);
                    
                    if (buffer->size() < stringPointerStart + stringLength) {
                        // ERROR
                        LOG->error ("getLabel: error 4");
                    } else {
                        result = std::make_shared<std::string>(
                                    (char*)buffer->data()+(stringPointerStart+1), 
                                    stringLength);
                        
                        //NOTE: Check if end of string or label
                        if (pointerReturnAddress == -1) {                            
                            pointerReturnAddress = (offset+2);
                            LOG->debug ("getLabel: pointerReturnAddress: %", 
                                        pointerReturnAddress);
                        } else {
                            LOG->debug ("getLabel: double indirection");
                        }
                        offset = stringPointerStart+1+stringLength;
                    }
                }
            }          
        } else {

            size_t stringLength = (size_t)buffer->at(offset);
            if (buffer->size() < offset + stringLength) {
                // ERROR
                LOG->error ("getLabel: error 5: stringLength: % offset: % size: %",
                            stringLength, 
                            offset, 
                            buffer->size());
            } else {
                result = std::make_shared<std::string>(
                            (char*)buffer->data()+(offset+1), 
                            stringLength);
                offset = offset + 1 + stringLength;
            }
        }
    }
    
    LOG->debug ("getLabel got: % offset: %", 
                (result?result->c_str():"NULL"),
                offset);
    
    return result;
}

std::string DnsPacket::getString (
    std::shared_ptr<std::vector<uint8_t>> buffer, 
    size_t& offset) 
{
 
    size_t cur = offset;
    std::string result;
    bool first = true;
    int32_t pointerReturnAddress = -1;
            
    std::shared_ptr<std::string> substr = nullptr;
    
    LOG->debug ("getString: offset: %", offset);
    
    do {        
        if (cur >= buffer->size()) {
            substr = nullptr;
            LOG->error ("getString: Error packet->size: % cursor: %", 
                        buffer->size(), 
                        cur);
        } else {
            substr = getLabel (buffer, cur, pointerReturnAddress);
            if (substr != nullptr) {            
                if (!first) {
                    result.append(".");
                } else {
                    first = false;
                }
                result.append (*substr);
            } else if (pointerReturnAddress != -1) {                
                LOG->debug ("getString: returning from pointer at: % next: %", 
                            cur, 
                            (uint8_t)buffer->at(cur));
            }
        }
    } while (substr != nullptr);
    
    if (pointerReturnAddress != -1) {
        offset = pointerReturnAddress;
    } else {
        offset = cur + 1;
    }
        
    LOG->debug ("getString got: %", result);
    
    return result;
}

std::shared_ptr<DnsPacket::Packet> DnsPacket::Parse (
    std::shared_ptr<std::vector<uint8_t>> buffer) 
{

    LOG->debug("Parse: --START--");
  
    auto packet = std::make_shared<Packet>();

    size_t cursor = 0;
    
    packet->transactionId = ntohs (getUint16 (buffer, cursor));
    packet->flags         = ntohs (getUint16 (buffer, cursor));
    packet->questionsRRS  = ntohs (getUint16 (buffer, cursor));
    packet->answerRRS     = ntohs (getUint16 (buffer, cursor));
    packet->authorityRRS  = ntohs (getUint16 (buffer, cursor));
    packet->additionalRRS = ntohs (getUint16 (buffer, cursor));
    
    LOG->debug ("parse: transactionId: %", packet->transactionId);
    LOG->debug ("parse: questions: %", packet->questionsRRS);
    LOG->debug ("parse: answerRRS: %", packet->answerRRS);
    LOG->debug ("parse: authorityRRS: %", packet->authorityRRS);
    LOG->debug ("parse: additionalRRS: %", packet->additionalRRS);

    // Questions
    for (int i = 0; i < packet->questionsRRS; ++i) {

        LOG->debug ("parse: question: % of %", i, packet->questionsRRS);
        auto question    = std::make_shared<Question>();         
        question->name   = getString (buffer, cursor);        
        question->qtype  = ntohs (getUint16 (buffer, cursor));
        question->qclass = ntohs (getUint16 (buffer, cursor));
        question->unicast = !(question->qclass & 0x8000U);
        packet->questions.push_back (question);
        LOG->debug ("parse: got question name: % type: % class: %", 
                    question->name, 
                    question->qtype, 
                    question->qclass);
    }

    for (int i = 0; i < packet->answerRRS; i++) {
        auto record = parseRecord (buffer, cursor, ENTRYTYPE_ANSWER);
        if (record) {
            packet->records.push_back (record);
        }
    }
    
    for (int i = 0; i < packet->authorityRRS; i++) {
        auto record = parseRecord (buffer, cursor, ENTRYTYPE_AUTHORITY);
        if (record) {
            packet->records.push_back (record);
        }
    }
    
    for (int i = 0; i < packet->additionalRRS; i++) {
        auto record = parseRecord (buffer, cursor, ENTRYTYPE_ADDITIONAL);
        if (record) {
            packet->records.push_back (record);
        }
    }
    
    LOG->debug("Parse: --END--");
    
    return packet;
}

std::shared_ptr<DnsPacket::Record> DnsPacket::parseRecord (
    std::shared_ptr<std::vector<uint8_t>> buffer,
    size_t& cursor,
    entry_type_t type) 
{
    auto record = std::make_shared<DnsPacket::Record>();
    
    record->name = getString (buffer, cursor);    
    record->rtype  = ntohs(getUint16 (buffer, cursor));
    
    LOG->debug ("parseRecord: got name: % type: %", record->name.c_str(), record->rtype);

    record->rclass = ntohs(getUint16 (buffer, cursor));
    record->ttl    = getUint32 (buffer, cursor);
    record->length = ntohs(getUint16 (buffer, cursor));
        
    if (record->rtype == RECORDTYPE_A) {        
        LOG->debug ("parseRecord: got RECORDTYPE_A");
        
        record->cacheFlush = record->rclass & CACHE_FLUSH;
        
        memset ((void*)&record->data.a, 0, sizeof(struct sockaddr_in));
        record->data.a.sin_family = AF_INET;
        #ifdef __APPLE__
        record->data.a.sin_len = sizeof(struct sockaddr_in);
        #endif
        if ((buffer->size() >= cursor + record->length) && (record->length == 4)) {
            std::memcpy (&record->data.a.sin_addr.s_addr, buffer->data()+cursor, 4);
            cursor = cursor + 4;
        }
    } else if (record->rtype == RECORDTYPE_AAAA) {
      
        LOG->debug ("parseRecord: got RECORDTYPE_AAAA");
        
        record->cacheFlush = record->rclass & CACHE_FLUSH;
        
        memset ((void*)&record->data.aaaa, 0, sizeof(struct sockaddr_in));
        record->data.aaaa.sin6_family = AF_INET6;
        #ifdef __APPLE__
        record->data.aaaa.sin6_len = sizeof(struct sockaddr_in6);
        #endif
        if ((buffer->size() >= cursor + record->length) && (record->length == 16)) {          
            std::memcpy (&record->data.aaaa.sin6_addr, buffer->data()+cursor, 16);
            cursor = cursor + 16;
        }
            
    } else {
        LOG->debug ("parseRecord: ignoring record type: %", record->rtype);
        cursor = cursor + record->length;
    }
        
    return record;
}

}
