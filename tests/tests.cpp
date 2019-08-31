#include <cassert>
#include <string>
#include <Logger.hpp>
#include "Client.hpp"

auto LOG = MDns::Logger::Get("tests");
std::shared_ptr<MDns::Client> mdns1;
std::shared_ptr<MDns::Client> mdns2;

void test_2();
void test_end();

/**
 * Test 1: regular query
 */
auto test_1_mdns1_callback = std::make_shared<MDns::Client::CallbackA> ([](bool error, const std::string& name, const std::string& ipAddress) {
  
    assert (!error);
    assert (name == mdns2->getLocalDomain());
    assert (!ipAddress.empty());
  
    std::cout << "[TEST] 1 OK" << std::endl;
    
    test_2();
    
});

void test_1 (uv_timer_t* handle) {
    //mdns1->queryA ("45553d06-2976-4c8f-b555-232471943c98.local", mdns1Callback, 500);
    mdns1->queryA (mdns2->getLocalDomain(), test_1_mdns1_callback, 500);
}

/**
 * Test 2: timeout
 */
auto test_2_mdns1_callback = std::make_shared<MDns::Client::CallbackA> ([](bool error, const std::string& name, const std::string& ipAddress) {
    assert (error);
    assert (name == "nonexistant");
    assert (ipAddress.empty());
    std::cout << "[TEST]: 2 OK" << std::endl;
    test_end();
});

void test_2 () {
    mdns1->queryA ("nonexistant", test_2_mdns1_callback, 500);
}

/**
 * Tests END
 */
void test_end() {
    mdns1.reset();
    mdns2.reset();
    std::cout << "[TEST]: END" << std::endl;
}

int main (int argc, char* argv[]) {
   
//     MDnsLog::setLogFunction ([](
//           MDnsLog::LOG_LEVEL level,
//           const std::string& tag,
//           const std::string& line) 
//     {
//         printf ("[TEST]: %s\n", line.c_str());
//     });
    
    LOG->setLogLevel (MDns::Logger::INFO);
  
    mdns1 = MDns::Client::New (uv_default_loop());
    mdns2 = MDns::Client::New (uv_default_loop());
    
    uv_timer_t timerHandle;
    uv_timer_init (uv_default_loop(), &timerHandle);
    timerHandle.data = nullptr;
    uv_timer_start (&timerHandle, &test_1, 50, 0);
    
    if (uv_run (uv_default_loop(), UV_RUN_DEFAULT) != 0) {
        std::cout << "[TEST]: error on uv_run" << std::endl;
    }
    
    uv_close ((uv_handle_t *)&timerHandle, [](uv_handle_t* handle) {
        
    });
    
    if (uv_run (uv_default_loop(), UV_RUN_DEFAULT) != 0) {
        std::cout << "[TEST]: error on uv_run" << std::endl;
    }
        
    if (uv_loop_close (uv_default_loop()) != 0) {
        std::cout << "[TEST]: error on uv_loop_close" << std::endl;
    }

    return 0;
    
}
