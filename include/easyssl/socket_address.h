#ifndef EASYSSL_SOCKET_ADDRESS_H
#define EASYSSL_SOCKET_ADDRESS_H


#ifdef _WIN32
#include <ws2tcpip.h>
#elif defined(linux) || defined(__APPLE__)
#include <sys/socket.h>
#endif


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


#endif //EASYSSL_SOCKET_ADDRESS_H
