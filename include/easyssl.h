#ifndef EASYSSL_H
#define EASYSSL_H


//windows definitions
#ifdef _WIN32


#include <WinSock2.h>
#include <ws2tcpip.h>


#ifdef min
#undef min
#endif


#ifdef max
#undef max
#endif


/**
 * Socket handle type.
 */
#define EASYSSL_SOCKET_HANDLE SOCKET


//else linux/apple definitions
#elif defined(linux) || defined(__APPLE__)


#include <sys/socket.h>
#include <netinet/ip.h> 


/**
 * Socket handle type.
 */
#define EASYSSL_SOCKET_HANDLE SOCKET int


#endif


#ifdef __cplusplus
extern "C" {
#endif


/**
 * False value.
 */
#define EASYSSL_FALSE 0


/**
 * True value.
 */
#define EASYSSL_TRUE 1


/**
 * Invalid socket handle type.
 */
#define EASYSSL_INVALID_SOCKET_HANDLE -1


/**
 * Boolean type.
 */
typedef int EASYSSL_BOOL;


//forward declarations
struct EASYSSL_SECURITY_DATA_STRUCT;
struct EASYSSL_SOCKET_STRUCT;


/**
 * Security data type.
 */
typedef struct EASYSSL_SECURITY_DATA_STRUCT* EASYSSL_SECURITY_DATA;


/**
 * Socket type.
 */
typedef struct EASYSSL_SOCKET_STRUCT* EASYSSL_SOCKET;


/**
 * Socket address union.
 * Provided in order to eliminate casts to sockaddr.
 */
typedef union EASYSSL_SOCKET_ADDRESS {
    /**
     * generic socket address structure.
     */
    struct sockaddr sa;

    /**
     * Socket address for IPV4.
     */
    struct sockaddr_in sa4;

    /**
     * Socket address for IPV6.
     */
    struct sockaddr_in6 sa6;

    /**
     * socket address storage.
     */
    struct sockaddr_storage ss;
} EASYSSL_SOCKET_ADDRESS;


/**
 * Error category. 
 */
enum EASYSSL_ERROR_CATEGORY {
    /**
     * System error; error can be retrieved from the 'errno' variable. 
     */
    EASYSSL_ERROR_SYSTEM,

    /**
     * Sockets error; valid on Windows only; error can be retrieved by the WSAGetLastError() function. 
     */
    EASYSSL_ERROR_WINSOCK,

    /**
     * Openssl error; error can be retrieved by the ERR_get_error() function.
     */
    EASYSSL_ERROR_OPENSSL,

    /**
     * Easyssl error.
     */
    EASYSSL_ERROR_EASYSSL
};


/**
 * Error structure. 
 */
typedef struct EASYSSL_ERROR {
    /**
     * Error category. 
     */
    int category;

    /**
     * Error number. 
     */
    int number;
} EASYSSL_ERROR;


/**
 * Error string buffer size. 
 */
#define EASYSSL_ERROR_STRING_BUFFER_SIZE 4096


/**
 * Socket status.
 */
enum EASYSSL_SOCKET_STATUS {
    /**
     * Socket closed.
     */
    EASYSSL_SOCKET_CLOSED = -2,

    /**
     * Socket operation needs retry.
     */
    EASYSSL_SOCKET_RETRY = -1,

    /**
     * Socket error.
     */
    EASYSSL_SOCKET_ERROR = 0,

    /**
     * Operation completed successfully. 
     */
    EASYSSL_SOCKET_OK = 1
};


/**
 * easy sll errors 
 */
enum EASYSSL_ERROR_NUMBER {
    /**
     * Peer had no certificate. 
     */
    EASYSSL_ERROR_NO_PEER_CERTIFICATE
};


/**
 * LOG level.
 */
enum EASYSSL_LOG_LEVEL {
    EASYSSL_LOG_LEVEL_MIN = 0,

    /**
     * Log nothing (the default in release builds, via NDEBUG defined).
     */
    EASYSSL_LOG_LEVEL_NOTHING = EASYSSL_LOG_LEVEL_MIN,

    /**
     * Log information.
     */
    EASYSSL_LOG_LEVEL_INFORMATION,

    /**
     * Log information and warnings.
     */
     EASYSSL_LOG_LEVEL_WARNING,

    /**
     * Log information, warnings and errors (the default in debug builds, via NDEBUG being undefined).
     */
    EASYSSL_LOG_LEVEL_ERROR,

    EASYSSL_LOG_LEVEL_MAX = EASYSSL_LOG_LEVEL_ERROR,
};


/**
 * Initializes the networking and SSL system.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_init();


/**
 * Cleans up the SSL and networking system.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_cleanup();


/**
 * Creates the security data required for creating a secure socket.
 * @return security data or NULL if the operation fails.
 */
EASYSSL_SECURITY_DATA EASYSSL_create_security_data();


/**
 * Adds a verify directory.
 * @param sd security data.
 * @param dir directory.
 * @return true on success, false on failure.
 */
EASYSSL_BOOL EASYSSL_add_verify_dir(EASYSSL_SECURITY_DATA sd, const char* dir);


/**
 * Adds a verify file.
 * @param sd security data.
 * @param file file.
 * @return true on success, false on failure.
 */
EASYSSL_BOOL EASYSSL_add_verify_file(EASYSSL_SECURITY_DATA sd, const char* file);


/**
 * Adds a verify store.
 * @param sd security data.
 * @param store store.
 * @return true on success, false on failure.
 */
EASYSSL_BOOL EASYSSL_add_verify_store(EASYSSL_SECURITY_DATA sd, const char* store);


/**
 * Adds a certificate chain file.
 * @param sd security data.
 * @param file file.
 * @return true on success, false on failure.
 */
EASYSSL_BOOL EASYSSL_add_certificate_chain_file(EASYSSL_SECURITY_DATA sd, const char* file);


/**
 * Adds a certificate file.
 * @param sd security data.
 * @param file file.
 * @return true on success, false on failure.
 */
EASYSSL_BOOL EASYSSL_add_certificate_file(EASYSSL_SECURITY_DATA sd, const char* file);


/**
 * Adds a private key file.
 * @param sd security data.
 * @param file file.
 * @return true on success, false on failure.
 */
EASYSSL_BOOL EASYSSL_add_private_key_file(EASYSSL_SECURITY_DATA sd, const char* file);


/**
 * Destroys the security data.
 * It must not be called while sockets are being used.
 * @param security_data security data to destroy.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_destroy_security_data(EASYSSL_SECURITY_DATA security_data);


/**
 * Opens a secure socket.
 * If the socket type is SOCK_STREAM.
 * @param security_data security data.
 * @param address_family address family.
 * @param socket_type socket type.
 * @param protocol protocol.
 * @param blocking if true, then the socket is blocking, else it is non-blocking.
 * @return the created socket or NULL if the operation fails.
 */
EASYSSL_SOCKET EASYSSL_socket(EASYSSL_SECURITY_DATA security_data, int address_family, int socket_type, int protocol, EASYSSL_BOOL blocking);


/**
 * Returns the socket handle.
 * @param socket socket to get the socket handle of.
 * return socket handle value or EASYSSL_INVALID_SOCKET_HANDLE if there was an error. 
 * @return true on success, false otherwise.
 */
EASYSSL_SOCKET_HANDLE EASYSSL_get_socket_handle(EASYSSL_SOCKET socket);


/**
 * Shuts down a socket.
 * @param socket socket to shut down.
 * @return socket status (see EASYSSL_SOCKET_STATUS enumeration).
 */
int EASYSSL_shutdown(EASYSSL_SOCKET socket);


/**
 * Closes a socket.
 * First, it shuts down the socket.
 * @param socket socket to close.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_close(EASYSSL_SOCKET socket);


/**
 * Binds a socket to an address.
 * @param socket socket to bind.
 * @param addr address to bind the socket to.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_bind(EASYSSL_SOCKET socket, const EASYSSL_SOCKET_ADDRESS* addr);


/**
 * Sets the socket to listen mode.
 * @param socket socket to set to listen mode.
 * @param backlog size of connection queue; valid for tcp sockets only.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_listen(EASYSSL_SOCKET socket, int backlog);


/**
 * Accepts a connection.
 * Does the SSL handshake, and the appropriate verifications.
 * @param socket socket to create a socket from.
 * @param new_socket pointer to set the new socket to.
 * @param addr address to bind the socket to.
 * @return socket status (see EASYSSL_SOCKET_STATUS enumeration).
 */
int EASYSSL_accept(EASYSSL_SOCKET socket, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr);


/**
 * Connects a socket to an address.
 * Does the SSL handshake, and the appropriate verifications.
 * @param socket socket to bind.
 * @param addr address to bind the socket to.
 * @return socket status (see EASYSSL_SOCKET_STATUS enumeration).
 */
int EASYSSL_connect(EASYSSL_SOCKET socket, const EASYSSL_SOCKET_ADDRESS* addr);


/**
 * Sends data to a connected peer.
 * @param socket socket to send data to.
 * @param buffer buffer with data.
 * @param buffer_size number of bytes to send; must be greater than 0.
 * @return bytes sent, or socket status (see EASYSSL_SOCKET_STATUS enumeration).
 */
int EASYSSL_send(EASYSSL_SOCKET socket, const void* buffer, int buffer_size);


/**
 * Receives data from a connected peer.
 * @param socket socket to receive data from.
 * @param buffer buffer to store the received data.
 * @param buffer_size number of bytes to receive.
 * @return bytes received, or socket status (see EASYSSL_SOCKET_STATUS enumeration).
 */
int EASYSSL_recv(EASYSSL_SOCKET socket, void* buffer, int buffer_size);


/**
 * Retrieves a socket option.
 * @param socket socket to retrieve an option of.
 * @param level socket option level.
 * @param name socket option name.
 * @param opt variable to store the option.
 * @param len option length.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_getsockopt(EASYSSL_SOCKET socket, int level, int name, void* opt, int len);


/**
 * Sets a socket option.
 * @param socket socket to set an option of.
 * @param level socket option level.
 * @param name socket option name.
 * @param opt variable that contains the option.
 * @param len option length.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_setsockopt(EASYSSL_SOCKET socket, int level, int name, const void* opt, int len);


/**
 * Returns the address a socket is bound to.
 * @param socket socket.
 * @param addr result address.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_getsockname(EASYSSL_SOCKET socket, EASYSSL_SOCKET_ADDRESS* addr);


/**
 * Returns the address a socket is connected to.
 * @param socket socket.
 * @param addr result address.
 * @return true on success, false otherwise.
 */
EASYSSL_BOOL EASYSSL_getpeername(EASYSSL_SOCKET socket, EASYSSL_SOCKET_ADDRESS* addr);


/**
 * Returns the last error.
 * Internally, each thread has its own version of the error struct.
 * @return pointer to the thread's error struct.
 */
const EASYSSL_ERROR* EASYSSL_get_last_error();


/**
 * Retrieves the string that corresponds to the given error.
 * @param error error to get the string of.
 * @param buffer pointer to buffer.
 * @param buffer_size size of buffer; preferrable size: EASYSSL_ERROR_STRING_BUFFER_SIZE.
 * @return true on success, false on error.
 */
EASYSSL_BOOL EASYSSL_get_error_string(const EASYSSL_ERROR* error, char* buffer, int buffer_size);


/**
 * Returns the log level.
 */
int EASYSSL_get_log_level();


/**
 * Sets the log level.
 * @param level log level.
 * @return true on success, false if the level is invalid.
 */
EASYSSL_BOOL EASYSSL_set_log_level(int level);


#ifdef __cplusplus
} //extern "C"
#endif //__cplusplus


#endif //EASYSSL_H
