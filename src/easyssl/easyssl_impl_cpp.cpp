#include <string>
#include <thread>
#include "easyssl/easyssl_impl.h"
#include "easyssl/easyssl_impl.hpp"


namespace easyssl {


    //auto library initialization
    static struct init {
        init() {
            if (!EASYSSL_init()) {
                throw error(*EASYSSL_get_last_error());
            }
        }
        ~init() {
            EASYSSL_cleanup();
        }
    } init;


    //get error string
    static std::string get_error_string(const EASYSSL_ERROR& error) {
        char buffer[EASYSSL_ERROR_STRING_BUFFER_SIZE];
        EASYSSL_get_error_string(&error, buffer, sizeof(buffer));
        return buffer;
    }


    //The default constructor.
    error::error(const EASYSSL_ERROR& err) : std::runtime_error(get_error_string(err)), EASYSSL_ERROR(err) {
    }


    //Empty constructor.
    socket_address::socket_address() : addr{} {
    }


    //Constructor from ip4 address.
    socket_address::socket_address(const std::array<unsigned char, 4>& ip4_addr, uint16_t port) : addr{} {
        addr.sa4.sin_family = AF_INET;
        memcpy(&addr.sa4.sin_addr, ip4_addr.data(), 4);
        addr.sa4.sin_port = htons(port);
    }


    //Constructor from ip4 address.
    socket_address::socket_address(uint32_t ip4_addr, uint16_t port) : addr{} {
        addr.sa4.sin_family = AF_INET;
        uint32_t v = htonl(ip4_addr);
        memcpy(&addr.sa4.sin_addr, &v, 4);
        addr.sa4.sin_port = htons(port);
    }


    //Constructor from ip4 address.
    socket_address::socket_address(const in_addr& ip4_addr, uint16_t port) : addr{} {
        addr.sa4.sin_family = AF_INET;
        addr.sa4.sin_addr = ip4_addr;
        addr.sa4.sin_port = htons(port);
    }


    //Constructor from ip6 address.
    socket_address::socket_address(const std::array<unsigned char, 16>& ip6_addr, uint32_t zone_index, uint16_t port) : addr{} {
        addr.sa6.sin6_family = AF_INET6;
        memcpy(&addr.sa6.sin6_addr, ip6_addr.data(), 16);
        addr.sa6.sin6_scope_id = zone_index;
        addr.sa6.sin6_port = htons(port);
    }


    //Constructor from ip6 address.
    socket_address::socket_address(const in6_addr& ip6_addr, uint32_t zone_index, uint16_t port) : addr{} {
        addr.sa6.sin6_family = AF_INET6;
        memcpy(&addr.sa6.sin6_addr, &ip6_addr, 16);
        addr.sa6.sin6_scope_id = zone_index;
        addr.sa6.sin6_port = htons(port);
    }


    //The default constructor.
    security_data::security_data()
        : m_security_data(EASYSSL_create_security_data(), EASYSSL_destroy_security_data)
    {
    }


    //Adds a verification directory.
    void security_data::add_verify_dir(const char* dir) {
        if (!EASYSSL_add_verify_dir(m_security_data.get(), dir)) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Adds a verification file.
    void security_data::add_verify_file(const char* file) {
        if (!EASYSSL_add_verify_file(m_security_data.get(), file)) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Adds a verification store.
    void security_data::add_verify_store(const char* store) {
        if (!EASYSSL_add_verify_store(m_security_data.get(), store)) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Adds a certificate chain file.
    void security_data::add_certificate_chain_file(const char* file) {
        if (!EASYSSL_add_certificate_chain_file(m_security_data.get(), file)) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Adds a certificate file.
    void security_data::add_certificate_file(const char* file) {
        if (!EASYSSL_add_certificate_file(m_security_data.get(), file)) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Adds a private key file.
    void security_data::add_private_key_file(const char* file) {
        if (!EASYSSL_add_private_key_file(m_security_data.get(), file)) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Empty socket constructor.
    socket::socket() {
    }


    //Constructor from parameters.
    socket::socket(const security_data& sd, int af, int type, int proto, bool blocking)
        : m_security_data(sd.m_security_data)
        , m_socket(EASYSSL_socket(sd.m_security_data.get(), af, type, proto, blocking ? EASYSSL_TRUE : EASYSSL_FALSE), EASYSSL_close)
    {
        if (!m_socket.get()) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Returns true if the socket is empty.
    socket::operator bool() const {
        return static_cast<bool>(m_socket);
    }


    //Shuts down the socket.
    socket::io_result socket::shutdown(bool wait) {
        for (;;) {
            switch (EASYSSL_shutdown(m_socket.get())) {
                case EASYSSL_SOCKET_CLOSED:
                    return io_result::closed;

                case EASYSSL_SOCKET_RETRY:
                    if (!wait) {
                        std::this_thread::yield();
                        continue;
                    }
                    return io_result::retry;

                case EASYSSL_SOCKET_ERROR:
                    throw error(*EASYSSL_get_last_error());

                case EASYSSL_SOCKET_OK:
                    return io_result::ok;
            }

            throw std::logic_error("Unreachable code");
        }
    }


    //Binds the socket to the specific address.
    void socket::bind(const socket_address& addr) {
        if (!EASYSSL_bind(m_socket.get(), &addr.addr)) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Puts the socket in listen state.
    void socket::listen(int backlog) {
        if (!EASYSSL_listen(m_socket.get(), backlog)) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //Accepts a connection from a client.
    socket::io_result socket::accept(socket& new_socket, socket_address& addr) {
        EASYSSL_SOCKET s;

        switch (EASYSSL_accept(m_socket.get(), &s, &addr.addr)) {
            case EASYSSL_SOCKET_CLOSED:
                return io_result::closed;

            case EASYSSL_SOCKET_RETRY:
                return io_result::retry;

            case EASYSSL_SOCKET_ERROR:
                throw error(*EASYSSL_get_last_error());

            case EASYSSL_SOCKET_OK:
                new_socket.m_security_data = m_security_data;
                new_socket.m_socket = std::shared_ptr<EASYSSL_SOCKET_STRUCT>{ s, EASYSSL_close };
                return io_result::ok;
        }

        throw std::logic_error("Unreachable code");
    }


    //Connects to a server.
    socket::io_result socket::connect(const socket_address& addr) {
        switch (EASYSSL_connect(m_socket.get(), &addr.addr)) {
            case EASYSSL_SOCKET_CLOSED:
                return io_result::closed;

            case EASYSSL_SOCKET_RETRY:
                return io_result::retry;

            case EASYSSL_SOCKET_ERROR:
                throw error(*EASYSSL_get_last_error());

            case EASYSSL_SOCKET_OK:
                return io_result::ok;
        }

        throw std::logic_error("Unreachable code");
    }


    //Sends data.
    int socket::send(const void* buffer, int buffer_size) {
        //send
        int r = EASYSSL_send(m_socket.get(), buffer, buffer_size);

        //success
        if (r > 0) {
            return r;
        }

        //error
        switch (r) {
            case EASYSSL_SOCKET_CLOSED:
                return closed;

            case EASYSSL_SOCKET_ERROR:
                throw error(*EASYSSL_get_last_error());

            case EASYSSL_SOCKET_RETRY:
                return retry;
        }

        throw std::logic_error("Unreachable code");
    }


    //receives data.
    int socket::receive(void* buffer, int buffer_size) {
        //receive
        int r = EASYSSL_recv(m_socket.get(), buffer, buffer_size);

        //success
        if (r > 0) {
            return r;
        }

        //error
        switch (r) {
            case EASYSSL_SOCKET_CLOSED:
                return closed;

            case EASYSSL_SOCKET_ERROR:
                throw error(*EASYSSL_get_last_error());

            case EASYSSL_SOCKET_RETRY:
                return retry;
        }

        throw std::logic_error("Unreachable code");
    }


    //Returns the address this socket is bound to.
    socket_address socket::get_local_address() const {
        socket_address result;
        if (!EASYSSL_getsockname(m_socket.get(), &result.addr)) {
            throw error(*EASYSSL_get_last_error());
        }
        return result;
    }


    //Returns the address this socket is connected to.
    socket_address socket::get_remote_address() const {
        socket_address result;
        if (!EASYSSL_getpeername(m_socket.get(), &result.addr)) {
            throw error(*EASYSSL_get_last_error());
        }
        return result;
    }


    //internal constructor
    socket::socket(const std::shared_ptr<EASYSSL_SECURITY_DATA_STRUCT>& sd, const std::shared_ptr<EASYSSL_SOCKET_STRUCT>& sock) 
        : m_security_data(sd), m_socket(sock)
    {
    }


    //generic getsocktopt
    void socket::getsockopt(void* sock, int level, int name, void* val, int size) {
        if (!EASYSSL_getsockopt(static_cast<EASYSSL_SOCKET>(sock), level, name, &val, sizeof(val))) {
            throw error(*EASYSSL_get_last_error());
        }
    }


    //generic setsockopt
    void socket::setsockpt(void* sock, int level, int name, const void* val, int size) {
        if (!EASYSSL_setsockopt(static_cast<EASYSSL_SOCKET>(sock), level, name, &val, sizeof(val))) {
            throw error(*EASYSSL_get_last_error());
        }
    }


} //namespace easyssl
