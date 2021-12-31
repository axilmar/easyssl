#ifndef EASYSSL_ERROR_H
#define EASYSSL_ERROR_H


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


#endif //EASYSSL_ERROR_H
