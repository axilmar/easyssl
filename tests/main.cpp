#include <vector>
#include <thread>
#include <string>
#include <atomic>
#include <mutex>
#include "easyssl.hpp"
#include "testlib.hpp"


using namespace testlib;
using namespace easyssl;


static void test_tcp_one_server_one_client() {
    socket_address server_addr(INADDR_LOOPBACK, 10000);
    static constexpr size_t test_message_count = 10;
    const std::string test_message = "hello server!!!";

    test("tcp, one server, one client", [&]() {
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


static void test_tcp_one_server_many_clients() {
    socket_address server_addr(INADDR_LOOPBACK, 10000);
    static constexpr size_t test_message_count = 10;
    const std::string test_message = "hello server!!!";
    static constexpr size_t test_client_count = 10;

    test("tcp, one server, many clients", [&]() {
        std::atomic<size_t> server_received_message_count{ 0 };

        std::atomic<size_t> thread_counter;
        std::mutex thread_mutex;
        std::vector<std::thread> threads;

        ++thread_counter;
        threads.push_back(std::thread([&]() {
            size_t client_created_count = 0;
            try {
                security_data sd;
                sd.add_verify_file("certs/ca.cert.pem");
                sd.add_certificate_file("certs/server.cert.pem");
                sd.add_private_key_file("certs/server.key.pem");
                easyssl::socket server_socket(sd, AF_INET, SOCK_STREAM, 0);
                server_socket.bind(server_addr);
                server_socket.listen();
                for (size_t i = 0; i < test_client_count; ++i) {
                    easyssl::socket client_socket;
                    socket_address client_address;
                    server_socket.accept(client_socket, client_address);
                    ++thread_counter;
                    std::lock_guard lock(thread_mutex);
                    threads.push_back(std::thread([&, client_socket]() mutable {
                        try {
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
                        --thread_counter;
                        }));
                }
            }
            catch (const std::exception& ex) {
                fail_test_with_exception(ex);
            }
            --thread_counter;
            }));

        for (size_t i = 0; i < test_client_count; ++i) {
            ++thread_counter;
            std::lock_guard lock(thread_mutex);
            threads.push_back(std::thread([&]() {
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
                --thread_counter;
                }));
        }

        while (thread_counter > 0) {
            std::this_thread::yield();
        }

        {
            std::lock_guard lock(thread_mutex);
            for (std::thread& thread : threads) {
                thread.join();
            }
        }

        check(server_received_message_count == test_message_count * test_client_count);
        });
}


int main() {
    testlib::init();
    test_tcp_one_server_one_client();
    test_tcp_one_server_many_clients();
    testlib::cleanup();
    system("pause");
    return 0;
}
