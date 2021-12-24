#pragma warning (disable: 4996)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include "easyssl/easyssl_impl.h"
#include "loglib.h"


///////////////////////////////////////////////////////////////////////////////////////////////////
//  PRIVATE MACROS
///////////////////////////////////////////////////////////////////////////////////////////////////


//thread local macro
#ifdef __GNUC__
# define thread_local __thread
#elif __STDC_VERSION__ >= 201112L
# define thread_local _Thread_local
#elif defined(_MSC_VER)
# define thread_local __declspec(thread)
#else
# error Cannot define thread_local
#endif


///////////////////////////////////////////////////////////////////////////////////////////////////
//  PRIVATE TYPES
///////////////////////////////////////////////////////////////////////////////////////////////////


//declare array type
#define ARRAY_TYPE(ELEMENT_TYPE, NAME)\
    typedef struct NAME {\
        ELEMENT_TYPE* data;\
        size_t count;\
    } NAME;


//string array
ARRAY_TYPE(char*, STRING_ARRAY)


//socket retry mode
enum SOCKET_RETRY_MODE {
    SOCKET_RETRY_NONE,
    SOCKET_RETRY_SYSCALL,
    SOCKET_RETRY_SSL
};


//mutex type
#ifdef _WIN32
typedef CRITICAL_SECTION MUTEX;
#else
#include <pthread.h>
typedef pthread_mutex_t MUTEX;
#endif


//security data struct
typedef struct EASYSSL_SECURITY_DATA_STRUCT {
    //mutex since this can be used by many threads within EASYSSL_connect().
    MUTEX mutex;

    //verify resources
    STRING_ARRAY verify_dirs;
    STRING_ARRAY verify_files;
    STRING_ARRAY verify_stores;

    //rsources
    STRING_ARRAY certificate_chain_files;
    STRING_ARRAY certificate_files;
    STRING_ARRAY private_key_files;

    //contexts
    SSL_CTX* tcp_server_ctx;
    SSL_CTX* udp_server_ctx;
    SSL_CTX* tcp_client_ctx;
    SSL_CTX* udp_client_ctx;
} EASYSSL_SECURITY_DATA_STRUCT;


//socket struct
typedef struct EASYSSL_SOCKET_STRUCT {
    //handle
    EASYSSL_SOCKET_HANDLE handle;

    //security data, required for context creation
    EASYSSL_SECURITY_DATA_STRUCT* security_data;

    //ssl object
    SSL* ssl;

    //socket type; 1 = stream, 0 = dgram
    int type_stream : 1;

    //retry mode; used for non-blocking sockets
    int retry_mode : 2;
} EASYSSL_SOCKET_STRUCT;


#define COOKIE_SECRET_LENGTH 64


//cookie verify context
typedef struct COOKIE_VERIFY_CONTEXT {
    unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
} COOKIE_VERIFY_CONTEXT;


///////////////////////////////////////////////////////////////////////////////////////////////////
//  PRIVATE VARIABLES
///////////////////////////////////////////////////////////////////////////////////////////////////


//thread error
static thread_local EASYSSL_ERROR thread_error = { 0, 0 };


//crypto locks
static MUTEX* crypto_mutexes = NULL;


///////////////////////////////////////////////////////////////////////////////////////////////////
//  PRIVATE FUNCTIONS
///////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////
//  MUTEX FUNCTIONS
//////////////////////////////////////////////////


#ifdef _WIN32
static int init_mutex(MUTEX* mutex) { InitializeCriticalSectionAndSpinCount(mutex, 10); return 0; }
static int destroy_mutex(MUTEX* m) { DeleteCriticalSection(m); return 0; }
static int lock_mutex(MUTEX* m) { EnterCriticalSection(m); return 0; }
static int unlock_mutex(MUTEX* m) { LeaveCriticalSection(m); return 0; }
#else
static int init_mutex(MUTEX* mutex) { pthread_mutex_init(mutex, NULL); }
static int destroy_mutex(MUTEX* m) { pthread_mutex_destroy(m); }
static int lock_mutex(MUTEX* m) { pthread_mutex_lock(m); }
static int unlock_mutex(MUTEX* m) { pthread_mutex_unlock(m); }
#endif


//////////////////////////////////////////////////
//  ARRAY FUNCTIONS
//////////////////////////////////////////////////


//array static initialization
#define ARRAY_INIT { NULL, 0 }


//array for each
#define ARRAY_FOR_EACH(A, CONTEXT, CB)\
    for(size_t i = 0; i < (A).count; ++i) {\
        CB(CONTEXT, (A).data[i]);\
    }


//array add
#define ARRAY_ADD(A, ELEM_TYPE, ELEM, COPY_CB) {\
        (A).data = (ELEM_TYPE*)realloc((A).data, sizeof(ELEM_TYPE) * ((A).count + 1));\
        (A).data[(A).count] = COPY_CB(ELEM);\
        ++(A).count;\
    }


//array cleanup
#define ARRAY_CLEANUP(A, DELETE_CB)\
    {\
        for(size_t i = (A).count; i > 0; --i) {\
            DELETE_CB((A).data[i - 1]);\
        }\
        free((A).data);\
    }


//////////////////////////////////////////////////
//  ERROR FUNCTIONS
//////////////////////////////////////////////////


//sets and logs the error depending on log level
static void set_error(int category, int number) {
    thread_error.category = category;
    thread_error.number = number;
    #ifndef EASYSSL_ERROR_LOGGING_DISABLED
    char buffer[EASYSSL_ERROR_STRING_BUFFER_SIZE];
    EASYSSL_get_error_string(&thread_error, buffer, sizeof(buffer));
    LOGLIB_log_error(buffer);
    #endif
}


//sets and logs the given error depending on log level
static void set_error_va_list(int category, int number, const char* format, va_list args) {
    thread_error.category = category;
    thread_error.number = number;
    #ifndef EASYSSL_ERROR_LOGGING_DISABLED
    char buffer[EASYSSL_ERROR_STRING_BUFFER_SIZE];
    vsnprintf(buffer, sizeof(buffer), format, args);
    LOGLIB_log_error(buffer);
    #endif
}


//sets errno, then the error
static void set_errno(int err) {
    errno = err;
    set_error(EASYSSL_ERROR_SYSTEM, err);
}


//sets errno, then the error
static void set_errno_va_list(int err, const char* format, va_list args) {
    errno = err;
    set_error_va_list(EASYSSL_ERROR_SYSTEM, err, format, args);
}


//clears the thread error
static void clear_thread_error() {
    thread_error.category = 0;
    thread_error.number = 0;
}


//clears all errors
static void clear_errors() {
    clear_thread_error();
    errno = 0;
    #ifdef _WIN32
    WSASetLastError(0);
    #endif
    ERR_clear_error();
}


//handle socket eror
static void handle_socket_error() {
#ifdef _WIN32
    set_error(EASYSSL_ERROR_WINSOCK, WSAGetLastError());
#else
    set_error(EASYSSL_ERROR_SYSTEM, errno);
#endif
}


//set error einval, log error
static void set_einval(const char* format, ...) {
    va_list args;
    va_start(args, format);
    set_errno_va_list(EINVAL, format, args);
    va_end(args);
}


//handle syscall error
static void handle_syscall_error() {
    //try a winsock error
#ifdef _WIN32
    if (WSAGetLastError()) {
        set_error(EASYSSL_ERROR_WINSOCK, WSAGetLastError());
        return;
    }
#endif

    //try a system error
    if (errno) {
        set_error(EASYSSL_ERROR_SYSTEM, errno);
        return;
    }

    //try an ssl error
    if (ERR_peek_error()) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
        return;
    }

    //no error could be found
    set_einval("Did not find a socket error, a system error or an SSL error.");
}


//////////////////////////////////////////////////
//  STRING FUNCTIONS
//////////////////////////////////////////////////


//copies a string to the given pointer, if not null;
//returns success/failure, depending on if string duplication suceeded.
static EASYSSL_BOOL copy_string(char** dst, const char* src) {
    if (src) {
        //duplicate string
        *dst = strdup(src);

        //return success/failure
        return *dst ? EASYSSL_TRUE : EASYSSL_FALSE;
    }

    //set to null
    *dst = NULL;
    return EASYSSL_TRUE;
}


//////////////////////////////////////////////////
//  SOCKET FUNCTIONS
//////////////////////////////////////////////////


//close a socket handle
static void close_socket(EASYSSL_SOCKET_HANDLE sock) {
#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}


//set socket blocking operation
static EASYSSL_BOOL do_set_socket_blocking(EASYSSL_SOCKET_HANDLE socket, EASYSSL_BOOL blocking) {
#ifdef _WIN32
    unsigned long mode = blocking ? 0 : 1;
    return (ioctlsocket(socket, FIONBIO, &mode) == 0) ? EASYSSL_TRUE : EASYSSL_FALSE;
#else
    int flags = fcntl(socket, F_GETFL, 0);
    if (flags == -1) return EASYSSL_FALSE;
    flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return (fcntl(fd, F_SETFL, flags) == 0) ? EASYSSL_TRUE : EASYSSL_FALSE;
#endif
}


//set socket blocking
static EASYSSL_BOOL set_socket_blocking(EASYSSL_SOCKET_HANDLE socket, EASYSSL_BOOL blocking) {
    if (!do_set_socket_blocking(socket, blocking)) {
        handle_socket_error();
        return EASYSSL_FALSE;
    }
    return EASYSSL_TRUE;
}


//check if the last error means to retry the operation later
static EASYSSL_BOOL socket_error_is_wait() {
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}


//crypto locking callback
static void crypto_locking_callback(int mode, int type, const char* file, int line) {
    if (mode & CRYPTO_LOCK) {
        lock_mutex(crypto_mutexes + type);
    }
    else {
        unlock_mutex(crypto_mutexes + type);
    }
}


//////////////////////////////////////////////////
//  SHUTDOWN FUNCTIONS
//////////////////////////////////////////////////


//handle shutdown result from SSL_shutdown
static int handle_shutdown_result_SSL_shutdown(EASYSSL_SOCKET socket, int r) {
    //success
    if (r == 1) {
        return EASYSSL_SOCKET_OK;
    }

    //retry
    if (r == 0) {
        socket->retry_mode = SOCKET_RETRY_SSL;
        return EASYSSL_SOCKET_RETRY;
    }

    //error
    switch (SSL_get_error(socket->ssl, r)) {
        case SSL_ERROR_NONE:
            socket->retry_mode = SOCKET_RETRY_NONE;
            return EASYSSL_SOCKET_OK;

        case SSL_ERROR_ZERO_RETURN:
            socket->retry_mode = SOCKET_RETRY_NONE;
            return EASYSSL_SOCKET_CLOSED;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            socket->retry_mode = SOCKET_RETRY_SSL;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            socket->retry_mode = SOCKET_RETRY_NONE;
            handle_syscall_error();
            return EASYSSL_SOCKET_ERROR;

        case SSL_ERROR_SSL:
            socket->retry_mode = SOCKET_RETRY_NONE;
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            return EASYSSL_SOCKET_ERROR;
    }

    set_einval("Unknown error returned by SSL_get_error in function handle_shutdown_result_SSL_shutdown.");
    return EASYSSL_SOCKET_ERROR;

}


//handle shutdown result from SSL_read
static int handle_shutdown_result_SSL_read(EASYSSL_SOCKET socket, int r) {
    switch (SSL_get_error(socket->ssl, r)) {
        case SSL_ERROR_NONE:
            socket->retry_mode = SOCKET_RETRY_NONE;
            return EASYSSL_SOCKET_OK;

        case SSL_ERROR_ZERO_RETURN:
            socket->retry_mode = SOCKET_RETRY_NONE;
            return EASYSSL_SOCKET_CLOSED;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            socket->retry_mode = SOCKET_RETRY_SSL;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            socket->retry_mode = SOCKET_RETRY_NONE;
            handle_syscall_error();
            return EASYSSL_SOCKET_ERROR;

        case SSL_ERROR_SSL:
            socket->retry_mode = SOCKET_RETRY_NONE;
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            return EASYSSL_SOCKET_ERROR;
    }

    set_einval("Unknown error returned by SSL_get_error in function handle_shutdown_result_SSL_read.");
    return EASYSSL_SOCKET_ERROR;
}


//handle shutdown result
static int handle_shutdown_result(EASYSSL_SOCKET socket, int r) {
    switch (socket->retry_mode) {
        case SOCKET_RETRY_NONE:
            return handle_shutdown_result_SSL_shutdown(socket, r);

        case SOCKET_RETRY_SSL:
            return handle_shutdown_result_SSL_read(socket, r);
    }

    set_einval("Invalid socket retry mode in function handle_shutdown_result.");
    return EASYSSL_SOCKET_ERROR;
}


//shutdown init
static int shutdown_init(EASYSSL_SOCKET socket) {
    //clear errors, in order to later find out which error mechanism was used
    clear_errors();

    //shutdown
    int r = SSL_shutdown(socket->ssl);

    //handle shutdown result
    return handle_shutdown_result(socket, r);
}


//shutdown ssl
static int shutdown_ssl(EASYSSL_SOCKET socket) {
    char buf[1];

    //read
    int r = SSL_read(socket->ssl, buf, sizeof(buf));

    //handle shutdown result
    return handle_shutdown_result(socket, r);
}


//////////////////////////////////////////////////
//  COOKIE VERIFICATION FUNCTIONS
//////////////////////////////////////////////////


//init cookie verify context
static EASYSSL_BOOL init_cookie_verify_context(SSL* ssl) {
    //alloc context
    COOKIE_VERIFY_CONTEXT* cookie_verify_context = (COOKIE_VERIFY_CONTEXT*)malloc(sizeof(COOKIE_VERIFY_CONTEXT));

    //if allocation failed
    if (!cookie_verify_context) {
        return EASYSSL_FALSE;
    }

    //set random data
    if (RAND_bytes(cookie_verify_context->cookie_secret, COOKIE_SECRET_LENGTH) != 1) {
        return EASYSSL_FALSE;
    }

    //set the given data as the app data of the ssl connection in order to access those data later from the callbacks
    SSL_set_app_data(ssl, cookie_verify_context);

    //success
    return EASYSSL_TRUE;
}


//generate cookie
static int generate_cookie(SSL* ssl, unsigned char* cookie, size_t* cookie_len) {
    EASYSSL_SOCKET_ADDRESS peer;
    unsigned int result_length;

    memset(&peer, 0, sizeof(peer));

    //get the peer address
    BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    //the cookie secret is stored in the verify context which is stored in the app data
    COOKIE_VERIFY_CONTEXT* cvc = SSL_get_app_data(ssl);

    //calculate the hmac
    HMAC(EVP_sha1(), (const void*)cvc->cookie_secret, COOKIE_SECRET_LENGTH, (const unsigned char*)&peer, sizeof(peer), cookie, &result_length);

    //success
    *cookie_len = result_length;
    return 1;
}


//verify cookie
static int verify_cookie(SSL* ssl, const unsigned char* cookie, size_t cookie_len) {
    EASYSSL_SOCKET_ADDRESS peer;
    unsigned char result[EVP_MAX_MD_SIZE];
    unsigned int result_length;

    memset(&peer, 0, sizeof(peer));

    //get the peer address
    BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    //the cookie secret is stored in the verify context which is stored in the app data
    COOKIE_VERIFY_CONTEXT* cvc = SSL_get_app_data(ssl);

    //calculate the hmac
    HMAC(EVP_sha1(), (const void*)cvc->cookie_secret, COOKIE_SECRET_LENGTH, (const unsigned char*)&peer, sizeof(peer), result, &result_length);

    //compare result length and cookie
    return result_length == cookie_len && memcmp(cookie, result, cookie_len) == 0;
}


//delete cookie verify context
static void delete_cookie_verify_context(SSL* ssl) {
    void* cookie_verify_data = SSL_get_app_data(ssl);
    free(cookie_verify_data);
}


//////////////////////////////////////////////////
//  SSL CONTEXT FUNCTIONS
//////////////////////////////////////////////////


//add resource macro
#define ADD_SECURITY_DATA_RESOURCE(SD, A, VAL)\
{\
    if (!SD) {\
        set_einval("Security data pointer is null in function %s.", __func__);\
        return EASYSSL_FALSE;\
    }\
    ARRAY_ADD(A, char*, VAL, strdup);\
    return EASYSSL_TRUE;\
}


//destroy context
static void destroy_context(SSL_CTX* ctx) {
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}


//loads a verify dir
static void load_verify_dir(SSL_CTX* ctx, const char* dir) {
    if (SSL_CTX_load_verify_dir(ctx, dir) != 1) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
    }
}


//loads a verify file
static void load_verify_file(SSL_CTX* ctx, const char* file) {
    if (SSL_CTX_load_verify_file(ctx, file) != 1) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
    }
}


//loads a verify store
static void load_verify_store(SSL_CTX* ctx, const char* store) {
    if (SSL_CTX_load_verify_store(ctx, store) != 1) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
    }
}


//uses a certificate chain file
static void use_certificate_chain_file(SSL_CTX* ctx, const char* file) {
    if (SSL_CTX_use_certificate_chain_file(ctx, file) != 1) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
    }
}


//uses a certificate file
static void use_certificate_file(SSL_CTX* ctx, const char* file) {
    if (SSL_CTX_use_certificate_file(ctx, file, SSL_FILETYPE_PEM) != 1) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
    }
}


//uses a private key file
static void use_private_key_file(SSL_CTX* ctx, const char* file) {
    if (SSL_CTX_use_PrivateKey_file(ctx, file, SSL_FILETYPE_PEM) != 1) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
    }
}


//load the certificates/key for a context
static EASYSSL_BOOL load_security_data(EASYSSL_SECURITY_DATA_STRUCT* sd, SSL_CTX* ctx) {
    //clear error
    clear_thread_error();

    //load files
    ARRAY_FOR_EACH(sd->verify_dirs            , ctx, load_verify_dir           );
    ARRAY_FOR_EACH(sd->verify_files           , ctx, load_verify_file          );
    ARRAY_FOR_EACH(sd->verify_stores          , ctx, load_verify_store         );
    ARRAY_FOR_EACH(sd->certificate_chain_files, ctx, use_certificate_chain_file);
    ARRAY_FOR_EACH(sd->certificate_files      , ctx, use_certificate_file      );
    ARRAY_FOR_EACH(sd->private_key_files      , ctx, use_private_key_file      );

    //if there was an error
    if (thread_error.number) {
        return EASYSSL_FALSE;
    }

    //success
    return EASYSSL_TRUE;
}


//handle created context
static SSL_CTX* handle_context_creation(EASYSSL_SECURITY_DATA_STRUCT* sd, SSL_CTX** sd_member, SSL_CTX* ctx) {
    //if failed to create the context
    if (!ctx) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
        return NULL;
    }

    //load the security data
    if (!load_security_data(sd, ctx)) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    //set the cipher list
    SSL_CTX_set_cipher_list(ctx, OSSL_default_ciphersuites());

    //set the verification mode
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    //success; set the sd member; return the context
    *sd_member = ctx;
    return ctx;
}


//get or create tcp server context
static SSL_CTX* tcp_get_or_create_server_context(EASYSSL_SECURITY_DATA_STRUCT* sd) {
    lock_mutex(&sd->mutex);

    //if already created, do nothing else
    if (sd->tcp_server_ctx) {
        unlock_mutex(&sd->mutex);
        return sd->tcp_server_ctx;
    }

    //create the context
    SSL_CTX* result = handle_context_creation(sd, &sd->tcp_server_ctx, SSL_CTX_new(TLS_server_method()));

    //if failure
    if (!result) {
        return NULL;
    }

    //set cookie verification methods
    SSL_CTX_set_stateless_cookie_generate_cb(result, generate_cookie);
    SSL_CTX_set_stateless_cookie_verify_cb(result, verify_cookie);

    //success
    unlock_mutex(&sd->mutex);
    return result;
}


//get or create tcp client context
static SSL_CTX* tcp_get_or_create_client_context(EASYSSL_SECURITY_DATA_STRUCT* sd) {
    lock_mutex(&sd->mutex);

    //if already created, do nothing else
    if (sd->tcp_client_ctx) {
        unlock_mutex(&sd->mutex);
        return sd->tcp_client_ctx;
    }

    //create the context
    SSL_CTX* result = handle_context_creation(sd, &sd->tcp_client_ctx, SSL_CTX_new(TLS_client_method()));

    //success
    unlock_mutex(&sd->mutex);
    return result;
}


//verify connection
static EASYSSL_BOOL verify_connection(SSL* ssl) {
    /*
    //if there is no certificate, fail
    if (!SSL_get0_peer_certificate(ssl)) {
        set_error(EASYSSL_ERROR_EASYSSL, EASYSSL_ERROR_NO_PEER_CERTIFICATE);
        return EASYSSL_FALSE;
    }
    */

    //if verification failed, fail
    long lr = SSL_get_verify_result(ssl);
    if (lr != X509_V_OK) {
        set_error(EASYSSL_ERROR_OPENSSL, lr);
        return EASYSSL_FALSE;
    }

    return EASYSSL_TRUE;
}


//////////////////////////////////////////////////
//  TCP ACCEPT FUNCTIONS
//////////////////////////////////////////////////


//failure cleanup for tcp accept
static void tcp_accept_failure_cleanup(EASYSSL_SOCKET sock) {
    //cleanup the ssl
    if (sock->ssl) {
        //also free cookie verify data
        delete_cookie_verify_context(sock->ssl);

        //also close the socket
        EASYSSL_SOCKET_HANDLE handle = SSL_get_fd(sock->ssl);
        close_socket(handle);

        //free the ssl
        SSL_free(sock->ssl);
    }

    //cleanup the socket
    sock->retry_mode = SOCKET_RETRY_NONE;
    sock->ssl = NULL;

}


//tcp ssl accept success
static int tcp_accept_ssl_success(EASYSSL_SOCKET sock, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    if (!verify_connection(sock->ssl)) {
        tcp_accept_failure_cleanup(sock);
        return EASYSSL_SOCKET_ERROR;
    }

    //if verification failed, fail
    long lr = SSL_get_verify_result(sock->ssl);
    if (lr != X509_V_OK) {
        set_error(EASYSSL_ERROR_OPENSSL, lr);
        tcp_accept_failure_cleanup(sock);
        return EASYSSL_SOCKET_ERROR;
    }

    //allocate memory for new socket
    EASYSSL_SOCKET_STRUCT* new_sock = (EASYSSL_SOCKET_STRUCT*)malloc(sizeof(EASYSSL_SOCKET_STRUCT));

    //if failed to create a socket
    if (!new_sock) {
        set_error(EASYSSL_ERROR_SYSTEM, errno);
        tcp_accept_failure_cleanup(sock);
        return EASYSSL_SOCKET_ERROR;
    }

    //setup the new socket
    new_sock->handle = SSL_get_fd(sock->ssl);
    new_sock->security_data = sock->security_data;
    new_sock->ssl = sock->ssl;
    new_sock->type_stream = sock->type_stream;
    new_sock->retry_mode = SOCKET_RETRY_NONE;

    //return the new socket
    *new_socket = new_sock;

    //restore the socket's tcp no delay value
    char off = 0;
    setsockopt(new_sock->handle, IPPROTO_TCP, TCP_NODELAY, &off, sizeof(off));

    //cleanup
    sock->retry_mode = SOCKET_RETRY_NONE;
    sock->ssl = NULL;
    delete_cookie_verify_context(new_sock->ssl);
    SSL_set_app_data(new_sock->ssl, NULL);

    //finally, the secure socket is created on the server side
    return EASYSSL_SOCKET_OK;
}


//tcp ssl accept
static int tcp_accept_ssl(EASYSSL_SOCKET sock, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    int r = SSL_accept(sock->ssl);

    switch (SSL_get_error(sock->ssl, r)) {
        case SSL_ERROR_NONE:
            return tcp_accept_ssl_success(sock, new_socket, addr);

        case SSL_ERROR_ZERO_RETURN:
            set_error(EASYSSL_ERROR_OPENSSL, SSL_ERROR_ZERO_RETURN);
            tcp_accept_failure_cleanup(sock);
            return EASYSSL_SOCKET_CLOSED;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            sock->retry_mode = SOCKET_RETRY_SSL;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            handle_syscall_error();
            tcp_accept_failure_cleanup(sock);
            return EASYSSL_SOCKET_ERROR;

        case SSL_ERROR_SSL:
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            tcp_accept_failure_cleanup(sock);
            return EASYSSL_SOCKET_ERROR;
    }

    set_einval("Unknown error returned by SSL_get_error in function tcp_accept_ssl.");
    return EASYSSL_SOCKET_ERROR;
}


//tcp socket accept
static int tcp_accept_socket(EASYSSL_SOCKET sock, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    //accept a connection
    int addrlen = sizeof(struct sockaddr_storage);
    EASYSSL_SOCKET_HANDLE handle = accept(sock->handle, &addr->sa, &addrlen);

    //handle error
    if (handle < 0) {
        //if error is wait, then retry
        if (socket_error_is_wait()) {
            sock->retry_mode = SOCKET_RETRY_SYSCALL;
            return EASYSSL_SOCKET_RETRY;
        }

        //otherwise, error
        handle_socket_error();
        return EASYSSL_SOCKET_ERROR;
    }

    //create the SSL
    SSL* ssl = SSL_new(sock->security_data->tcp_server_ctx);

    //if failed to create the ssl
    if (!ssl) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
        close_socket(handle);
        return EASYSSL_SOCKET_ERROR;
    }

    //set the socket handle
    SSL_set_fd(ssl, (int)handle);

    //in order to find the ssl in the next retry, set the socket's ssl to the new ssl
    sock->ssl = ssl;

    //init cookie verify context
    if (!init_cookie_verify_context(ssl)) {
        tcp_accept_failure_cleanup(sock);
        return EASYSSL_SOCKET_ERROR;
    }

    //turn Nagle's algorithm off for the handshake in order to allow ACK to be returned as soon as possible
    char on = 1;
    setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    //continue with ssl accept
    return tcp_accept_ssl(sock, new_socket, addr);
}


//tcp accept initialization
static int tcp_accept_init(EASYSSL_SOCKET sock, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    //the socket must not have an ssl
    if (sock->ssl) {
        set_einval("Invalid socket in function tcp_accept_init.");
        return EASYSSL_SOCKET_ERROR;
    }

    //create context for tcp if not yet created
    SSL_CTX* ctx = tcp_get_or_create_server_context(sock->security_data);

    //if failed to create context
    if (!ctx) {
        return EASYSSL_SOCKET_ERROR;
    }

    //continue with socket accept
    return tcp_accept_socket(sock, new_socket, addr);
}


//tcp accept
static int tcp_accept(EASYSSL_SOCKET sock, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    switch (sock->retry_mode) {
        case SOCKET_RETRY_NONE:
            return tcp_accept_init(sock, new_socket, addr);

        case SOCKET_RETRY_SYSCALL:
            return tcp_accept_socket(sock, new_socket, addr);

        case SOCKET_RETRY_SSL:
            return tcp_accept_ssl(sock, new_socket, addr);
    }

    //invalid retry mode
    set_einval("Invalid retry mode in function tcp_accept.");
    return EASYSSL_SOCKET_ERROR;
}


//////////////////////////////////////////////////
//  TCP CONNECT FUNCTIONS
//////////////////////////////////////////////////


//failure cleanup
static void tcp_connect_failure_cleanup(EASYSSL_SOCKET sock) {
    if (sock->ssl) {
        SSL_free(sock->ssl);
    }
    sock->ssl = NULL;
    sock->retry_mode = SOCKET_RETRY_NONE;
}


//ssl connect success
static int tcp_connect_ssl_success(EASYSSL_SOCKET sock) {
    //verify connection
    if (!verify_connection(sock->ssl)) {
        tcp_connect_failure_cleanup(sock);
        return EASYSSL_SOCKET_ERROR;
    }

    //success; restore the no delay parameter
    char tcp_nodelay = (char)SSL_get_app_data(sock->ssl);
    setsockopt(sock->handle, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));

    //cleanup the socket
    sock->retry_mode = SOCKET_RETRY_NONE;

    //finally, the socket is connected
    return EASYSSL_SOCKET_OK;
}


//connect ssl
static int tcp_connect_ssl(EASYSSL_SOCKET sock, const EASYSSL_SOCKET_ADDRESS* addr) {
    //ssl connect
    int r =  SSL_connect(sock->ssl);

    //handle error
    switch (SSL_get_error(sock->ssl, r)) {
        case SSL_ERROR_NONE:
            return tcp_connect_ssl_success(sock);

        case SSL_ERROR_ZERO_RETURN:
            tcp_connect_failure_cleanup(sock);
            set_error(EASYSSL_ERROR_OPENSSL, SSL_ERROR_ZERO_RETURN);
            return EASYSSL_SOCKET_CLOSED;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            sock->retry_mode = SOCKET_RETRY_SSL;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            tcp_connect_failure_cleanup(sock);
            handle_syscall_error();
            return EASYSSL_SOCKET_ERROR;

        case SSL_ERROR_SSL:
            tcp_connect_failure_cleanup(sock);
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            return EASYSSL_SOCKET_ERROR;
    }

    set_einval("Unknown error returned by SSL_get_error in function tcp_connect_ssl.");
    return EASYSSL_SOCKET_ERROR;
}


//connect socket
static int tcp_connect_socket(EASYSSL_SOCKET sock, const EASYSSL_SOCKET_ADDRESS* addr) {
    //connect the socket
    if (connect(sock->handle, &addr->sa, sizeof(struct sockaddr_storage))) {
        //retry on wait
        if (socket_error_is_wait()) {
            sock->retry_mode = SOCKET_RETRY_SYSCALL;
            return EASYSSL_SOCKET_RETRY;
        }

        //actual error
        handle_socket_error();
        return EASYSSL_SOCKET_ERROR;
    }

    //create the SSL
    SSL* ssl = SSL_new(sock->security_data->tcp_client_ctx);

    //if failed to create the ssl
    if (!ssl) {
        set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
        return EASYSSL_SOCKET_ERROR;
    }

    //set the socket handle
    SSL_set_fd(ssl, (int)sock->handle);

    //keep the current no delay option of the socket
    char tcp_nodelay;
    int optlen = sizeof(tcp_nodelay);
    getsockopt(sock->handle, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, &optlen);
    SSL_set_app_data(ssl, tcp_nodelay);

    //turn Nagle's algorithm off for the handshake in order to allow ACK to be returned as soon as possible
    char on = 1;
    setsockopt(sock->handle, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    //store the ssl in the socket 
    sock->ssl = ssl;

    //continue with ssl connect
    return tcp_connect_ssl(sock, addr);
}


//init connect
static int tcp_connect_init(EASYSSL_SOCKET sock, const EASYSSL_SOCKET_ADDRESS* addr) {
    //the socket must not have an ssl
    if (sock->ssl) {
        set_einval("Invalid socket in function tcp_connect_init.");
        return EASYSSL_SOCKET_ERROR;
    }

    //create context for tcp if not yet created
    SSL_CTX* ctx = tcp_get_or_create_client_context(sock->security_data);

    //if failed to create context
    if (!ctx) {
        return EASYSSL_SOCKET_ERROR;
    }

    //continue with connecting the socket
    return tcp_connect_socket(sock, addr);
}


//tcp connect
static int tcp_connect(EASYSSL_SOCKET sock, const EASYSSL_SOCKET_ADDRESS* addr) {
    switch (sock->retry_mode) {
        case SOCKET_RETRY_NONE:
            return tcp_connect_init(sock, addr);

        case SOCKET_RETRY_SYSCALL:
            return tcp_connect_socket(sock, addr);

        case SOCKET_RETRY_SSL:
            return tcp_connect_ssl(sock, addr);
    }

    set_einval("Invalid retry mode in function tcp_connect.");
    return EASYSSL_SOCKET_ERROR;
}


//////////////////////////////////////////////////
//  UDP ACCEPT FUNCTIONS
//////////////////////////////////////////////////


//udp accept
static int udp_accept(EASYSSL_SOCKET sock, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    //TODO
    return 0;
}


//////////////////////////////////////////////////
//  UDP CONNECT FUNCTIONS
//////////////////////////////////////////////////


//udp connect
static EASYSSL_BOOL udp_connect(EASYSSL_SOCKET socket, const EASYSSL_SOCKET_ADDRESS* addr) {
    //TODO
    return EASYSSL_TRUE;
}


///////////////////////////////////////////////////////////////////////////////////////////////////
//  PUBLIC FUNCTIONS
///////////////////////////////////////////////////////////////////////////////////////////////////


//init
EASYSSL_BOOL EASYSSL_init() {
    //init sockets
    #ifdef _WIN32
    WSADATA wsadata;
    int r = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (r) {
        set_error(EASYSSL_ERROR_WINSOCK, WSAGetLastError());
        return EASYSSL_FALSE;
    }
    #endif

    //init openssl
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    ENGINE_load_builtin_engines();

    //init crypto locking
    crypto_mutexes = (MUTEX*)malloc(sizeof(MUTEX) * CRYPTO_num_locks());
    for (size_t i = 0; i < CRYPTO_num_locks(); ++i) {
        init_mutex(crypto_mutexes + i);
    }
    CRYPTO_set_locking_callback(crypto_locking_callback);

    //init logging
    LOGLIB_init();

    return EASYSSL_TRUE;
}


//cleanup
EASYSSL_BOOL EASYSSL_cleanup() {
    //cleanup crypto locking
    CRYPTO_set_locking_callback(NULL);
    for (size_t i = 0; i < CRYPTO_num_locks(); ++i) {
        destroy_mutex(crypto_mutexes + i);
    }
    free(crypto_mutexes);

    //clenaup openssl
    ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    //cleanup sockets
    #ifdef _WIN32
    int r = WSACleanup();
    if (r) {
        set_error(EASYSSL_ERROR_WINSOCK, WSAGetLastError());
        return EASYSSL_FALSE;
    }
    #endif

    //cleanup logging
    LOGLIB_cleanup();

    return EASYSSL_TRUE;
}


//create security data
EASYSSL_SECURITY_DATA EASYSSL_create_security_data() {
    EASYSSL_SECURITY_DATA_STRUCT* sd;

    //allocate sd
    sd = (EASYSSL_SECURITY_DATA_STRUCT*)malloc(sizeof(EASYSSL_SECURITY_DATA_STRUCT));

    //handle allocation failure
    if (!sd) {
        set_error(EASYSSL_ERROR_SYSTEM, errno);
        return NULL;
    }

    //reset sd
    memset(sd, 0, sizeof(EASYSSL_SECURITY_DATA_STRUCT));

    //init other fields
    init_mutex(&sd->mutex);

    //success
    return sd;
}


//adds a verify dir
EASYSSL_BOOL EASYSSL_add_verify_dir(EASYSSL_SECURITY_DATA sd, const char* dir) {
    ADD_SECURITY_DATA_RESOURCE(sd, sd->verify_dirs, dir);
}


//Adds a verify file.
EASYSSL_BOOL EASYSSL_add_verify_file(EASYSSL_SECURITY_DATA sd, const char* file) {
    ADD_SECURITY_DATA_RESOURCE(sd, sd->verify_files, file);
}


//Adds a verify store.
EASYSSL_BOOL EASYSSL_add_verify_store(EASYSSL_SECURITY_DATA sd, const char* store) {
    ADD_SECURITY_DATA_RESOURCE(sd, sd->verify_stores, store);
}


//Adds a certificate chain file.
EASYSSL_BOOL EASYSSL_add_certificate_chain_file(EASYSSL_SECURITY_DATA sd, const char* file) {
    ADD_SECURITY_DATA_RESOURCE(sd, sd->certificate_chain_files, file);
}


//Adds a certificate file.
EASYSSL_BOOL EASYSSL_add_certificate_file(EASYSSL_SECURITY_DATA sd, const char* file) {
    ADD_SECURITY_DATA_RESOURCE(sd, sd->certificate_files, file);
}


//Adds a key file.
EASYSSL_BOOL EASYSSL_add_private_key_file(EASYSSL_SECURITY_DATA sd, const char* file) {
    ADD_SECURITY_DATA_RESOURCE(sd, sd->private_key_files, file);
}


//destroy security data
EASYSSL_BOOL EASYSSL_destroy_security_data(EASYSSL_SECURITY_DATA sd) {
    //check param
    if (!sd) {
        set_einval("Null security data pointer.");
        return EASYSSL_FALSE;
    }

    //destroy contexts
    destroy_context(sd->tcp_server_ctx);
    destroy_context(sd->tcp_client_ctx);
    destroy_context(sd->udp_server_ctx);
    destroy_context(sd->udp_client_ctx);

    //free resources
    destroy_mutex(&sd->mutex);
    ARRAY_CLEANUP(sd->verify_dirs, free);
    ARRAY_CLEANUP(sd->verify_files, free);
    ARRAY_CLEANUP(sd->verify_stores, free);
    ARRAY_CLEANUP(sd->certificate_chain_files, free);
    ARRAY_CLEANUP(sd->certificate_files, free);
    ARRAY_CLEANUP(sd->private_key_files, free);

    //success
    return EASYSSL_TRUE;
}


//create socket
EASYSSL_SOCKET EASYSSL_socket(EASYSSL_SECURITY_DATA sd, int af, int st, int p, EASYSSL_BOOL blocking) {
    EASYSSL_SOCKET_STRUCT* sock;

    //check params
    if (!sd) {
        set_einval("Null security data pointer in function EASYSSL_socket.");
        return NULL;
    }
    if (st != SOCK_STREAM && st != SOCK_DGRAM) {
        set_einval("Unsupported socket type %i in function EASYSSL_socket.", st);
        return NULL;
    }

    //create the socket
    EASYSSL_SOCKET_HANDLE handle = socket(af, st, p);

    //handle socket creation error
    if (handle < 0) {
        handle_socket_error();
        return NULL;
    }

    //set the socket to non-blocking if requested
    if (!blocking && !set_socket_blocking(handle, EASYSSL_FALSE)) {
        close_socket(handle);
        return NULL;
    }

    //allocate memory for socket
    sock = (EASYSSL_SOCKET_STRUCT*)malloc(sizeof(EASYSSL_SOCKET_STRUCT));

    //handle allocation failure
    if (!sock) {
        close_socket(handle);
        set_error(EASYSSL_ERROR_SYSTEM, errno);
        return NULL;
    }

    //init the socket structure
    sock->handle = handle;
    sock->security_data = sd;
    sock->ssl = NULL;
    sock->type_stream = st == SOCK_STREAM;
    sock->retry_mode = SOCKET_RETRY_NONE;

    //success
    return sock;
}


//get handle
EASYSSL_SOCKET_HANDLE EASYSSL_get_socket_handle(EASYSSL_SOCKET socket) {
    //check param
    if (!socket) {
        set_einval("Null socket in function EASYSSL_get_socket_handle.");
        return EASYSSL_INVALID_SOCKET_HANDLE;
    }

    //return handle
    return socket->handle;
}


//shutdown socket
int EASYSSL_shutdown(EASYSSL_SOCKET socket) {
    //check param
    if (!socket) {
        set_einval("Null socket in function EASYSSL_shutdown.");
        return EASYSSL_SOCKET_ERROR;
    }

    //if no ssl, there is nothing to shutdown
    if (!socket->ssl) {
        return EASYSSL_SOCKET_OK;
    }

    //if already shutdown
    if (SSL_get_shutdown(socket->ssl)) {
        return EASYSSL_SOCKET_OK;
    }

    //handle retry mode
    switch (socket->retry_mode) {
        case SOCKET_RETRY_NONE:
            return shutdown_init(socket);

        case SOCKET_RETRY_SSL:
            return shutdown_ssl(socket);
    }

    set_einval("Invalid retry mode in function EASYSSL_shutdown.");
    return EASYSSL_SOCKET_ERROR;
}


//destroy a socket
EASYSSL_BOOL EASYSSL_close(EASYSSL_SOCKET socket) {
    //check param
    if (!socket) {
        set_einval("null socket in function EASYSSL_close.");
        return EASYSSL_FALSE;
    }

    //if ssl exists in the socket
    if (socket->ssl) {
        //shutdown the socket; wait for shutdown
        while (EASYSSL_shutdown(socket) == EASYSSL_SOCKET_RETRY) {
            #ifdef _WIN32
            Sleep(10);
            #else
            pthread_yield();
            #endif
        }

        //free its ssl part, if set
        SSL_free(socket->ssl);
    }

    //close the socket
    close_socket(socket->handle);

    //free the memory occupied by the socket
    free(socket);

    //success
    return EASYSSL_TRUE;
}


//bind a socket
EASYSSL_BOOL EASYSSL_bind(EASYSSL_SOCKET socket, const EASYSSL_SOCKET_ADDRESS* addr) {
    //check params
    if (!socket) {
        set_einval("null socket in function EASYSSL_bind.");
        return EASYSSL_FALSE;
    }
    if (!addr) {
        set_einval("null address in function EASYSSL_bind.");
        return EASYSSL_FALSE;
    }

    //bind the socket
    if (bind(socket->handle, &addr->sa, sizeof(struct sockaddr_storage))) {
        handle_socket_error();
        return EASYSSL_FALSE;
    }

    //success
    return EASYSSL_TRUE;
}


//set the socket to listen mode
EASYSSL_BOOL EASYSSL_listen(EASYSSL_SOCKET socket, int backlog) {
    //check param
    if (!socket) {
        set_einval("null socket in function EASYSSL_listen.");
        return EASYSSL_FALSE;
    }

    //listen only for SOCK_STREAM
    if (socket->type_stream && listen(socket->handle, backlog)) {
        return EASYSSL_FALSE;
    }

    //success
    return EASYSSL_TRUE;
}


//accept connection
int EASYSSL_accept(EASYSSL_SOCKET socket, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    //check param
    if (!socket) {
        set_einval("null socket in function EASYSSL_accept.");
        return EASYSSL_SOCKET_ERROR;
    }

    //handle socket type
    if (socket->type_stream) {
        return tcp_accept(socket, new_socket, addr);
    }
    return udp_accept(socket, new_socket, addr);
}


//connect
int EASYSSL_connect(EASYSSL_SOCKET socket, const EASYSSL_SOCKET_ADDRESS* addr) {
    //check param
    if (!socket) {
        set_einval("null socket in function EASYSSL_connect.");
        return EASYSSL_FALSE;
    }
    if (!addr) {
        set_einval("null address in function EASYSSL_connect.");
        return EASYSSL_FALSE;
    }

    //handle socket type
    if (socket->type_stream) {
        return tcp_connect(socket, addr);
    }
    return udp_connect(socket, addr);
}


//send data
int EASYSSL_send(EASYSSL_SOCKET socket, const void* buffer, int buffer_size) {
    int r;

    //check params
    if (!socket) {
        set_einval("Null socket in function EASYSSL_send.");
        return EASYSSL_SOCKET_ERROR;
    }
    if (!socket->ssl) {
        set_einval("Invalid socket in function EASYSSL_send.");
        return EASYSSL_SOCKET_ERROR;
    }
    if (buffer_size <= 0) {
        set_einval("Zero or negative buffer size in function EASYSSL_send.");
        return EASYSSL_SOCKET_ERROR;
    }

    //write data
    r = SSL_write(socket->ssl, buffer, buffer_size);

    //success
    if (r > 0) {
        return r;
    }

    //handle error
    switch (SSL_get_error(socket->ssl, r)) {
        case SSL_ERROR_ZERO_RETURN:
            return EASYSSL_SOCKET_CLOSED;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            handle_syscall_error();
            return EASYSSL_SOCKET_ERROR;

        case SSL_ERROR_SSL:
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            return EASYSSL_SOCKET_ERROR;
    }

    set_einval("Unknown error returned by SSL_get_error in function EASYSSL_send.");
    return EASYSSL_SOCKET_ERROR;
}


//receive data
int EASYSSL_recv(EASYSSL_SOCKET socket, void* buffer, int buffer_size) {
    int r;

    //check param
    if (!socket) {
        set_einval("Null socket in function EASYSSL_recv.");
        return EASYSSL_SOCKET_ERROR;
    }
    if (!socket->ssl) {
        set_einval("Invalid socket in function EASYSSL_recv.");
        return EASYSSL_SOCKET_ERROR;
    }
    if (buffer_size <= 0) {
        set_einval("Zero or negative buffer size in function EASYSSL_recv.");
        return EASYSSL_SOCKET_ERROR;
    }

    //read data
    r = SSL_read(socket->ssl, buffer, buffer_size);

    //success
    if (r > 0) {
        return r;
    }

    //handle error
    switch (SSL_get_error(socket->ssl, r)) {
        case SSL_ERROR_NONE:
            return r;

        case SSL_ERROR_ZERO_RETURN:
            return EASYSSL_SOCKET_CLOSED;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            handle_syscall_error();
            return EASYSSL_SOCKET_ERROR;

        case SSL_ERROR_SSL:
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            return EASYSSL_SOCKET_ERROR;
    }

    set_einval("Unknown error returned by SSL_get_error in function EASYSSL_recv.");
    return EASYSSL_SOCKET_ERROR;
}



//get socket option
EASYSSL_BOOL EASYSSL_getsockopt(EASYSSL_SOCKET socket, int level, int name, void* opt, int len) {
    //check param
    if (!socket) {
        set_einval("Null socket in function EASYSSL_getsockopt.");
        return EASYSSL_FALSE;
    }

    //get option
    if (getsockopt(socket->handle, level, name, opt, &len)) {
        handle_socket_error();
        return EASYSSL_FALSE;
    }

    //success
    return EASYSSL_TRUE;
}



//set socket option
EASYSSL_BOOL EASYSSL_setsockopt(EASYSSL_SOCKET socket, int level, int name, const void* opt, int len) {
    //check param
    if (!socket) {
        set_einval("Null socket in function EASYSSL_setsockopt.");
        return EASYSSL_FALSE;
    }

    //get option
    if (setsockopt(socket->handle, level, name, opt, len)) {
        handle_socket_error();
        return EASYSSL_FALSE;
    }

    //success
    return EASYSSL_TRUE;
}


//get bound address
EASYSSL_BOOL EASYSSL_getsockname(EASYSSL_SOCKET socket, EASYSSL_SOCKET_ADDRESS* addr) {
    //check param
    if (!socket) {
        set_einval("Null socket in function EASYSSL_getsockname.");
        return EASYSSL_FALSE;
    }

    //get name
    int namelen = sizeof(EASYSSL_SOCKET_ADDRESS);
    if (getsockname(socket->handle, &addr->sa, &namelen)) {
        handle_socket_error();
        return EASYSSL_FALSE;
    }

    //success
    return EASYSSL_TRUE;
}


//get connected address
EASYSSL_BOOL EASYSSL_getpeername(EASYSSL_SOCKET socket, EASYSSL_SOCKET_ADDRESS* addr) {
    //check param
    if (!socket) {
        set_einval("Null socket in function EASYSSL_getpeername.");
        return EASYSSL_FALSE;
    }

    //get name
    int namelen = sizeof(EASYSSL_SOCKET_ADDRESS);
    if (getpeername(socket->handle, &addr->sa, &namelen)) {
        handle_socket_error();
        return EASYSSL_FALSE;
    }

    //success
    return EASYSSL_TRUE;
}


//get error
const EASYSSL_ERROR* EASYSSL_get_last_error() {
    return &thread_error;
}


//Retrieves the string that corresponds to the given error.
EASYSSL_BOOL EASYSSL_get_error_string(const EASYSSL_ERROR* error, char* buffer, int buffer_size) {
    buffer[0] = '\0';

    //check params
    if (!error) {
        set_einval("Null error in function EASYSSL_get_error_string.");
        return EASYSSL_FALSE;
    }
    if (!buffer) {
        set_einval("Null buffer in function EASYSSL_get_error_string.");
        return EASYSSL_FALSE;
    }
    if (buffer_size <= 0) {
        set_einval("Zero or negative buffer size in function EASYSSL_get_error_string.");
        return EASYSSL_FALSE;
    }

    switch (error->category) {
        case EASYSSL_ERROR_SYSTEM:
            #ifdef _WIN32
            return strerror_s(buffer, buffer_size, error->number) ? EASYSSL_FALSE : EASYSSL_TRUE;
            #else
            return strerror_r(error->number, buffer, buffer_size) ? EASYSSL_FALSE : EASYSSL_TRUE;
            #endif

        #ifdef _WIN32
        case EASYSSL_ERROR_WINSOCK: {
            EASYSSL_BOOL ok = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error->number, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, buffer_size, NULL) > 0;
            return ok;
        }
        #endif

        case EASYSSL_ERROR_OPENSSL:
            ERR_error_string_n(error->number, buffer, buffer_size);
            return buffer[0] != '\0';

        case EASYSSL_ERROR_EASYSSL:
            switch (error->number) {
                case EASYSSL_ERROR_NO_PEER_CERTIFICATE: {
                    static const char msg[] = "Certificate verification failure: no peer certificate.";
                    if (sizeof(msg) > buffer_size) {
                        return EASYSSL_FALSE;
                    }
                    memcpy(buffer, msg, sizeof(msg));
                    return EASYSSL_TRUE;
                }
            }
    }

    //failure
    set_einval("Invalid error in function EASYSSL_get_error_string.");
    return EASYSSL_FALSE;
}
