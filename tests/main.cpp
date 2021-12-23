#include <thread>
#include <string>
#include <atomic>
#include "easyssl.hpp"
#include "testlib.hpp"


using namespace testlib;
using namespace easyssl;


static void test_tcp_one_server_one_client() {
    socket_address server_addr(INADDR_LOOPBACK, 10000);
    static constexpr size_t test_message_count = 10;
    const std::string test_message = "hello server!!!";

    test("tcp", [&]() {
        std::atomic<size_t> server_received_message_count{ 0 };

        std::thread server_thread([&]() {
            try {
                security_data sd;
                sd.add_verify_file("certs/ca.cert.pem");
                sd.add_certificate_file("certs/server.cert.pem");
                sd.add_private_key_file("certs/server.key.pem");
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
                security_data sd;
                sd.add_verify_file("certs/ca.cert.pem");
                sd.add_certificate_file("certs/client.cert.pem");
                sd.add_private_key_file("certs/client.key.pem");
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
    testlib::init();
    test_tcp_one_server_one_client();
    testlib::cleanup();
    system("pause");
    return 0;
}
