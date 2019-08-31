#include <stdio.h>
#include <stdarg.h>
#include <memory>
#include "Logger.hpp"

namespace MDns {
  
Logger::LOG_LEVEL Logger::_logLevel = Logger::DEBUG;
  
std::shared_ptr<Logger> Logger::Get(
   const std::string& tag)
{
    return std::shared_ptr<Logger>(new Logger(tag));
}

Logger::Logger (
    const std::string& tag
) 
{
    _logFunction = nullptr;
    _tag = tag;
}

Logger::~Logger() {
  
}

void Logger::setLogLevel (
    LOG_LEVEL level) 
{
    _logLevel = level;
}

void Logger::setLogFunction (
    std::function<void(LOG_LEVEL, 
                       const std::string& tag, 
                       const std::string& line)> f) 
{
    _logFunction = f;
}

std::string Logger::levelToString (
    LOG_LEVEL level) 
{
    switch (level) {
      case ERROR: return "E";
      case WARN:  return "W";
      case INFO:  return "I";
      case DEBUG: return "D";
      default: return "";
    }
}

void Logger::xsprintf (
    std::string& result, const char *s) 
{
    while (*s) {
        if (*s == '%') {
            if (*(s + 1) == '%') {
                ++s;
            } else {
                throw std::runtime_error("invalid format string: missing arguments");
            }
        }
        result += *s++;
    }
}

}
