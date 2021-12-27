#ifndef EASYSSL_SOCKET_STATUS_H
#define EASYSSL_SOCKET_STATUS_H


/**
 * Socket status.
 */
enum EASYSSL_SOCKET_STATUS {
    /**
     * Socket closed.
     */
    EASYSSL_SOCKET_CLOSED = -3,

    /**
     * Socket operation needs retry.
     */
     EASYSSL_SOCKET_RETRY = -2,

    /**
     * Socket connection refused.
     */
    EASYSSL_SOCKET_CONNECTION_REFUSED = -1,

    /**
     * Socket error.
     */
    EASYSSL_SOCKET_ERROR = 0,

    /**
     * Operation completed successfully.
     */
    EASYSSL_SOCKET_SUCCESS = 1,
};


#endif //EASYSSL_SOCKET_STATUS_H
