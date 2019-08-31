#ifndef __MDNS_LOGGER_HPP__
#define __MDNS_LOGGER_HPP__

#include <string>
#include <sstream>
#include <iostream>
#include <functional>
#include <memory>

namespace MDns {

class Logger {
  
public:
  
    typedef enum {
        NONE = 0,
        ERROR,
        WARN,
        INFO,
        DEBUG,
        NUM_LEVELS
    } LOG_LEVEL;
    
    static std::shared_ptr<Logger> Get (
        const std::string& tag);
    
    ~Logger();
    
    static void setLogLevel (
        LOG_LEVEL level);
  
    void setLogFunction (
        std::function<void(LOG_LEVEL level, 
        const std::string& tag,                   
        const std::string& line)>);
    
    template <typename... Args> 
    void debug (
        const std::string& fmt_str, 
        const Args &... args) 
    {
        formatAndPrint (DEBUG, fmt_str, args...); 
    }

    template <typename... Args> 
    void info (
        const std::string& fmt_str, 
        const Args &... args) 
    {
        formatAndPrint (INFO,  fmt_str, args...); 
    }

    template <typename... Args> 
    void warn (
        const std::string& fmt_str, 
        const Args &... args) 
    {
        formatAndPrint (WARN,  fmt_str, args...); 
    }

    template <typename... Args> 
    void error (
        const std::string& fmt_str, 
        const Args &... args) 
    {
        formatAndPrint (ERROR, fmt_str, args...); 
    }
    
private:
  
    static LOG_LEVEL _logLevel;
    
    std::function<void(
        LOG_LEVEL level, 
        const std::string& tag,
        const std::string& line)> _logFunction;
        
    std::string _tag;
    
    Logger (
        const std::string& tag);
    
    std::string levelToString (
        LOG_LEVEL level);
    
    void xsprintf (
        std::string& result, const char *s);

    template<typename T, typename... Args>
    void xsprintf (
        std::string& result, 
        const char *s, 
        T value, 
        Args... args) 
    {
        while (*s) {
            if (*s == '%') {
                if (*(s + 1) == '%') {
                    ++s;
                } else {
                    std::stringstream stream;
                    stream << value;
                    result += stream.str();
                    // call even when *s == 0 to detect extra arguments
                    xsprintf(result, s + 1, args...); 
                    return;
                }
            }
            result += *s++;
        }
        throw std::logic_error("extra arguments provided to printf");
    }

    template <typename... Args> 
    void formatAndPrint (
        LOG_LEVEL level, 
        const std::string& fmt_str, 
        const Args &... args) 
    {
        if (level <= _logLevel) {
            std::string line = "";
            xsprintf (line, fmt_str.c_str(), args...);
            if (_logFunction == nullptr) {
                std::cerr 
                << "-" << levelToString (level) << "-"
                << "[" << _tag <<  "]: "
                << line << std::endl;
            } else {
                _logFunction (level, _tag, line);
            }
        }
    }

};

}
#endif
