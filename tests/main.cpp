#include <thread>
#include <string>
#include <atomic>
#include "easyssl.hpp"
#include "testlib.hpp"


using namespace testlib;
using namespace easyssl;


static void test_tcp_one_server_one_client(const security_data& sd) {
    socket_address server_addr(INADDR_LOOPBACK, 10000);
    static constexpr size_t test_message_count = 10;
    const std::string test_message = "hello server!!!";

    test("tcp", [&]() {
        std::atomic<size_t> server_received_message_count{ 0 };

        std::thread server_thread([&]() {
            try {
                easyssl::socket server_socket(sd, AF_INET, SOCK_STREAM, 0);
                server_socket.bind(server_addr);
                server_socket.listen();
                easyssl::socket client_socket;
                socket_address client_address;
                server_socket.accept(client_socket, client_address);
                std::string str;
                str.resize(test_message.size());
                for (size_t i = 0; i < test_message_count; ++i) {
                    client_socket.receive(str.data(), (int)str.size());
                    check(str == test_message);
                    ++server_received_message_count;
                }
            }
            catch (const std::exception& ex) {
                fail_test_with_exception(ex);
            }
            });

        std::thread client_thread([&]() {
            try {
                easyssl::socket client_socket(sd, AF_INET, SOCK_STREAM, 0);
                client_socket.connect(server_addr);
                for (size_t i = 0; i < test_message_count; ++i) {
                    client_socket.send(test_message.data(), (int)test_message.size());
                }
            }
            catch (const std::exception& ex) {
                fail_test_with_exception(ex);
            }
            });

        client_thread.join();
        server_thread.join();

        check(server_received_message_count == test_message_count);
        });
}


int main() {
    security_data sd("netlib.pem", "netlib.key");
    testlib::init();
    test_tcp_one_server_one_client(sd);
    testlib::cleanup();
    system("pause");
    return 0;
}
