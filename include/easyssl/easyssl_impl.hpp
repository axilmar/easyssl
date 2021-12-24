#ifndef EASYSSL_EASYSSL_IMPL_HPP
#define EASYSSL_EASYSSL_IMPL_HPP


#include <stdexcept>
#include <memory>
#include <array>
#include <cstdint>
#include "socket_address.h"
#include "error.h"
#include "socket_status.h"


struct EASYSSL_SECURITY_DATA_STRUCT;
struct EASYSSL_SOCKET_STRUCT;


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
        error(const EASYSSL_ERROR& err);
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
        socket_address();

        /**
         * Constructor from ip4 address.
         * @param ip4_addr ip4 address.
         * @param port port number.
         */
        socket_address(const std::array<unsigned char, 4>& ip4_addr, uint16_t port);

        /**
         * Constructor from ip4 address.
         * @param ip4_addr ip4 address.
         * @param port port number.
         */
        socket_address(uint32_t ip4_addr, uint16_t port);

        /**
         * Constructor from ip4 address.
         * @param ip4_addr ip4 address.
         * @param port port number.
         */
        socket_address(const in_addr& ip4_addr, uint16_t port);

        /**
         * Constructor from ip6 address.
         * @param ip6_addr ip6 address.
         * @param zone_index zone index.
         * @param port port number.
         */
        socket_address(const std::array<unsigned char, 16>& ip6_addr, uint32_t zone_index, uint16_t port);

        /**
         * Constructor from ip6 address.
         * @param ip6_addr ip6 address.
         * @param zone_index zone index.
         * @param port port number.
         */
        socket_address(const in6_addr& ip6_addr, uint32_t zone_index, uint16_t port);
    };


    /**
     * Security data.
     */
    class security_data {
    public:
        /**
         * The default constructor.
         * An empty security data object is created.
         */
        security_data();

        /**
         * Adds a verification directory.
         * @param dir directory.
         * @exception easyssl::error thrown if there was an error.
         */
        void add_verify_dir(const char* dir);

        /**
         * Adds a verification file.
         * @param file file.
         * @exception easyssl::error thrown if there was an error.
         */
        void add_verify_file(const char* file);

        /**
         * Adds a verification store.
         * @param store store.
         * @exception easyssl::error thrown if there was an error.
         */
        void add_verify_store(const char* store);

        /**
         * Adds a certificate chain file.
         * @param file file.
         * @exception easyssl::error thrown if there was an error.
         */
        void add_certificate_chain_file(const char* file);

        /**
         * Adds a certificate file.
         * @param file file.
         * @exception easyssl::error thrown if there was an error.
         */
        void add_certificate_file(const char* file);

        /**
         * Adds a private key file.
         * @param file file.
         * @exception easyssl::error thrown if there was an error.
         */
        void add_private_key_file(const char* file);

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
        socket();

        /**
         * Constructor from parameters.
         * @param sd security data.
         * @param af address family.
         * @param type socket type.
         * @param proto protocol type.
         * @param blocking true for a blocking socket, false for a non-blocking socket.
         * @exception easyssl::error thrown if there was an error.
         */
        socket(const security_data& sd, int af, int type, int proto, bool blocking = true);

        /**
         * Returns true if the socket is empty.
         */
        explicit operator bool() const;

        /**
         * Shuts down the socket.
         * @param wait if true, then when it waits for shutdown before returning.
         * @return i/o result.
         * @exception easyssl::error thrown if there was an error.
         */
        io_result shutdown(bool wait = true);

        /**
         * Binds the socket to the specific address.
         * @param addr address to bind the socket to.
         * @exception easyssl::error thrown if there was an error.
         */
        void bind(const socket_address& addr);

        /**
         * Puts the socket in listen state.
         * @param backlog pending connection queue size.
         * @exception easyssl::error thrown if there was an error.
         */
        void listen(int backlog = SOMAXCONN);

        /**
         * Accepts a connection from a client.
         * @param new_socket new socket.
         * @param addr address of sender.
         * @return i/o result.
         * @exception easyssl::error thrown if there was an error.
         */
        io_result accept(socket& new_socket, socket_address& addr);

        /**
         * Connects to a server.
         * @param addr address of server.
         * @return i/o result.
         * @exception easyssl::error thrown if there was an error.
         */
        io_result connect(const socket_address& addr);

        /**
         * Sends data.
         * @param buffer buffer with data to send.
         * @return buffer_size number of bytes to send.
         * @return number of bytes sent, or io_result::closed if the socket is closed, or io_result::retry for non-blocking socket.
         * @exception easyssl::error thrown if there was an error.
         */
        int send(const void* buffer, int buffer_size);

        /**
         * receives data.
         * @param buffer buffer to store the received data.
         * @return buffer_size number of bytes to the received data can contain.
         * @return number of bytes sent, or io_result::closed if the socket is closed, or io_result::retry for non-blocking socket.
         * @exception easyssl::error thrown if there was an error.
         */
        int receive(void* buffer, int buffer_size);

        /**
         * Returns a socket option.
         * @param level option level.
         * @param name option name.
         * @return option value.
         * @exception easyssl::error thrown if there was an error.
         */
        template <class T> T get_option(int level, int name) {
            T val;
            getsockopt(m_socket.get(), level, name, &val, sizeof(val));
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
            setsockopt(m_socket.get(), level, name, &val, sizeof(val));
        }

        /**
         * Returns the address this socket is bound to.
         * @exception easyssl::error thrown if there was an error.
         */
        socket_address get_local_address() const;

        /**
         * Returns the address this socket is connected to.
         * @exception easyssl::error thrown if there was an error.
         */
        socket_address get_remote_address() const;

    private:
        std::shared_ptr<EASYSSL_SECURITY_DATA_STRUCT> m_security_data;
        std::shared_ptr<EASYSSL_SOCKET_STRUCT> m_socket;

        //internal constructor
        socket(const std::shared_ptr<EASYSSL_SECURITY_DATA_STRUCT>& sd, const std::shared_ptr<EASYSSL_SOCKET_STRUCT>& sock);

        //generic getsocktopt
        static void getsockopt(void* sock, int level, int name, void* val, int size);

        //generic setsockopt
        static void setsockpt(void* sock, int level, int name, const void* val, int size);
    };


} //namespace easyssl


#endif //EASYSSL_EASYSSL_IMPL_HPP
