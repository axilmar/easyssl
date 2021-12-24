#ifndef EASYSSL_ERROR_H
#define EASYSSL_ERROR_H


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
