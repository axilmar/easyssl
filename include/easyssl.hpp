#ifndef EASYSSL_HPP
#define EASYSSL_HPP


#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <cstdint>
#include "easyssl.h"


namespace easyssl {


    /**
     * Easysll error.
     */
    class error : public std::runtime_error, public EASYSSL_ERROR {
    public:
        /**
         * The default constructor.
         * @param err error.
         */
        error(const EASYSSL_ERROR& err) : std::runtime_error(get_error_string(err)), EASYSSL_ERROR(err) {
        }

    private:
        static std::string get_error_string(const EASYSSL_ERROR& error) {
            char buffer[65536];
            EASYSSL_get_error_string(&error, buffer, sizeof(buffer));
            return buffer;
        }
    };


    /**
     * Socket address wrapper.
     */
    class socket_address {
    public:
        /**
         * Socket address.
         */
        EASYSSL_SOCKET_ADDRESS addr;

        /**
         * Empty constructor.
         */
        socket_address() : addr{} {
        }

        /**
         * Constructor from ip4 address.
         * @param ip4_addr ip4 address.
         * @param port port number.
         */
        socket_address(const std::array<unsigned char, 4>& ip4_addr, uint16_t port) : addr{}  {
            addr.sa4.sin_family = AF_INET;
            memcpy(&addr.sa4.sin_addr, ip4_addr.data(), 4);
            addr.sa4.sin_port = htons(port);
        }

        /**
         * Constructor from ip4 address.
         * @param ip4_addr ip4 address.
         * @param port port number.
         */
        socket_address(uint32_t ip4_addr, uint16_t port) : addr{} {
            addr.sa4.sin_family = AF_INET;
            uint32_t v = htonl(ip4_addr);
            memcpy(&addr.sa4.sin_addr, &v, 4);
            addr.sa4.sin_port = htons(port);
        }

        /**
         * Constructor from ip4 address.
         * @param ip4_addr ip4 address.
         * @param port port number.
         */
        socket_address(const in_addr& ip4_addr, uint16_t port) : addr{} {
            addr.sa4.sin_family = AF_INET;
            addr.sa4.sin_addr = ip4_addr;
            addr.sa4.sin_port = htons(port);
        }

        /**
         * Constructor from ip6 address.
         * @param ip6_addr ip6 address.
         * @param zone_index zone index.
         * @param port port number.
         */
        socket_address(const std::array<unsigned char, 16>& ip6_addr, uint32_t zone_index, uint16_t port) : addr{} {
            addr.sa6.sin6_family = AF_INET6;
            memcpy(&addr.sa6.sin6_addr, ip6_addr.data(), 16);
            addr.sa6.sin6_scope_id = zone_index;
            addr.sa6.sin6_port = htons(port);
        }

        /**
         * Constructor from ip6 address.
         * @param ip6_addr ip6 address.
         * @param zone_index zone index.
         * @param port port number.
         */
        socket_address(const in6_addr& ip6_addr, uint32_t zone_index, uint16_t port) : addr{} {
            addr.sa6.sin6_family = AF_INET6;
            memcpy(&addr.sa6.sin6_addr, &ip6_addr, 16);
            addr.sa6.sin6_scope_id = zone_index;
            addr.sa6.sin6_port = htons(port);
        }
    };


    /**
     * Security data.
     */
    class security_data {
    public:
        /**
         * Empty constructor.
         */
        security_data() {
        }

        /**
         * Constructor from parameters.
         * It creates a security data object.
         * @param ca_path optional path to certificate authorities file directory.
         * @param ca_file optional path to certificate authorities file.
         * @param ca_store optional certificate authorities store.
         * @param ca_chain_file optional certificate authorities chain file.
         * @param key_file path to private key.
         * @exception easy_ssl::error thrown if there is an error.
         */
        security_data(const char* ca_path, const char* ca_file, const char* ca_store, const char* ca_chain_file, const char* key_file) 
            : m_security_data(EASYSSL_create_security_data(ca_path, ca_file, ca_store, ca_chain_file, key_file), EASYSSL_destroy_security_data)
        {
            if (!m_security_data.get()) {
                throw error(*EASYSSL_get_last_error());
            }
        }

        /**
         * Constructor from parameters.
         * It creates a security data object.
         * @param ca_file path to certificate authorities file.
         * @param key_file path to private key.
         * @exception easy_ssl::error thrown if there is an error.
         */
        security_data(const char* ca_path, const char* ca_file, const char* key_file)
            : security_data(ca_path, ca_file, nullptr, nullptr, key_file)
        {
        }

        /**
         * Constructor from parameters.
         * It creates a security data object.
         * @param ca_file path to certificate authorities file.
         * @param key_file path to private key.
         * @exception easy_ssl::error thrown if there is an error.
         */
        security_data(const char* ca_file, const char* key_file)
            : security_data(nullptr, ca_file, nullptr, nullptr, key_file)
        {
        }

    private:
        std::shared_ptr<EASYSSL_SECURITY_DATA_STRUCT> m_security_data;

        friend class socket;
    };


    /**
     * Socket.
     */
    class socket {
    public:
        /**
         * I/O result.
         */
        enum io_result {
            ///closed.
            closed = EASYSSL_SOCKET_CLOSED,

            ///retry.
            retry = EASYSSL_SOCKET_RETRY,

            ///success.
            ok = EASYSSL_SOCKET_OK
        };

        /**
         * Empty socket constructor.
         */
        socket() {
        }

        /**
         * Constructor from parameters.
         * @param sd security data.
         * @param af address family.
         * @param type socket type.
         * @param proto protocol type.
         * @param blocking true for a blocking socket, false for a non-blocking socket.
         * @exception easyssl::error thrown if there was an error.
         */
        socket(const security_data& sd, int af, int type, int proto, bool blocking = true)
            : m_security_data(sd.m_security_data)
            , m_socket(EASYSSL_socket(sd.m_security_data.get(), af, type, proto, blocking ? EASYSSL_TRUE : EASYSSL_FALSE), EASYSSL_close)
        {
            if (!m_socket.get()) {
                throw error(*EASYSSL_get_last_error());
            }
        }

        /**
         * Returns true if the socket is empty.
         */
        explicit operator bool() const {
            return static_cast<bool>(m_socket);
        }

        /**
         * Shuts down the socket.
         * @return i/o result.
         * @exception easyssl::error thrown if there was an error.
         */
        io_result shutdown() {
            switch (EASYSSL_shutdown(m_socket.get())) {
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

        /**
         * Binds the socket to the specific address.
         * @param addr address to bind the socket to.
         * @exception easyssl::error thrown if there was an error.
         */
        void bind(const socket_address& addr) {
            if (!EASYSSL_bind(m_socket.get(), &addr.addr)) {
                throw error(*EASYSSL_get_last_error());
            }
        }

        /**
         * Puts the socket in listen state.
         * @param backlog pending connection queue size.
         * @exception easyssl::error thrown if there was an error.
         */
        void listen(int backlog = SOMAXCONN) {
            if (!EASYSSL_listen(m_socket.get(), backlog)) {
                throw error(*EASYSSL_get_last_error());
            }
        }

        /**
         * Accepts a connection from a client.
         * @param new_socket new socket.
         * @param addr address of sender.
         * @return i/o result.
         * @exception easyssl::error thrown if there was an error.
         */
        io_result accept(socket& new_socket, socket_address& addr) {
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
                    new_socket.m_socket = std::shared_ptr<EASYSSL_SOCKET_STRUCT>{s, EASYSSL_close};
                    return io_result::ok;
            }

            throw std::logic_error("Unreachable code");
        }

        /**
         * Connects to a server.
         * @param addr address of server.
         * @return i/o result.
         * @exception easyssl::error thrown if there was an error.
         */
        io_result connect(const socket_address& addr) {
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

        /**
         * Sends data.
         * @param buffer buffer with data to send.
         * @return buffer_size number of bytes to send.
         * @return number of bytes sent, or io_result::closed if the socket is closed, or io_result::retry for non-blocking socket.
         * @exception easyssl::error thrown if there was an error.
         */
        int send(const void* buffer, int buffer_size) {
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

        /**
         * receives data.
         * @param buffer buffer to store the received data.
         * @return buffer_size number of bytes to the received data can contain.
         * @return number of bytes sent, or io_result::closed if the socket is closed, or io_result::retry for non-blocking socket.
         * @exception easyssl::error thrown if there was an error.
         */
        int receive(void* buffer, int buffer_size) {
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

        /**
         * Returns a socket option.
         * @param level option level.
         * @param name option name.
         * @return option value.
         * @exception easyssl::error thrown if there was an error.
         */
        template <class T> T get_option(int level, int name) {
            T val;
            if (!EASYSSL_getsockopt(m_socket.get(), level, name, &val, sizeof(val))) {
                throw error(*EASYSSL_get_last_error());
            }
            return val;
        }

        /**
         * Sets a socket option.
         * @param level option level.
         * @param name option name.
         * @param val option value.
         * @exception easyssl::error thrown if there was an error.
         */
        template <class T> void set_option(int level, int name, const T& val) {
            if (!EASYSSL_setsockopt(m_socket.get(), level, name, &val, sizeof(val))) {
                throw error(*EASYSSL_get_last_error());
            }
        }

        /**
         * Returns the address this socket is bound to.
         * @exception easyssl::error thrown if there was an error.
         */
        socket_address get_local_address() const {
            socket_address result;
            if (!EASYSSL_getsockname(m_socket.get(), &result.addr)) {
                throw error(*EASYSSL_get_last_error());
            }
            return result;
        }

        /**
         * Returns the address this socket is connected to.
         * @exception easyssl::error thrown if there was an error.
         */
        socket_address get_remote_address() const {
            socket_address result;
            if (!EASYSSL_getpeername(m_socket.get(), &result.addr)) {
                throw error(*EASYSSL_get_last_error());
            }
            return result;
        }

    private:
        std::shared_ptr<EASYSSL_SECURITY_DATA_STRUCT> m_security_data;
        std::shared_ptr<EASYSSL_SOCKET_STRUCT> m_socket;
        socket(const std::shared_ptr<EASYSSL_SECURITY_DATA_STRUCT>& sd, const std::shared_ptr<EASYSSL_SOCKET_STRUCT>& sock) : m_security_data(sd), m_socket(sock) {}

    };


} //namespace easyssl


#endif //EASYSSL_HPP
