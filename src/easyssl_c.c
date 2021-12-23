#pragma warning (disable: 4996)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "easyssl.h"


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


//mutex
#ifdef _WIN32
typedef CRITICAL_SECTION MUTEX;
static int init_mutex(MUTEX* mutex) { InitializeCriticalSectionAndSpinCount(mutex, 10); return 0; }
static int destroy_mutex(MUTEX* m) { DeleteCriticalSection(m); return 0; }
static int lock_mutex(MUTEX* m) { EnterCriticalSection(m); return 0; }
static int unlock_mutex(MUTEX* m) { LeaveCriticalSection(m); return 0; }
#else
#include <pthread.h>
typedef pthread_mutex_t MUTEX;
static int init_mutex(MUTEX* mutex) { pthread_mutex_init(mutex, NULL); }
static int destroy_mutex(MUTEX* m) { pthread_mutex_destroy(m); }
static int lock_mutex(MUTEX* m) { pthread_mutex_lock(m); }
static int unlock_mutex(MUTEX* m) { pthread_mutex_unlock(m); }
#endif


//security data struct
typedef struct EASYSSL_SECURITY_DATA_STRUCT {
    //mutex since this can be used by many threads within EASYSSL_connect().
    MUTEX mutex;

    //paths
    char* ca_path;
    char* ca_file;
    char* ca_store;
    char* ca_chain_file;
    char* key_file;

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

    //type; 1 = stream, 0 = dgram
    int type : 1;

    //retry mode; used for non-blocking sockets
    int retry : 1;
} EASYSSL_SOCKET_STRUCT;


#define COOKIE_SECRET_LENGTH 64


//cookie verify context
typedef struct COOKIE_VERIFY_CONTEXT {
    unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
} COOKIE_VERIFY_CONTEXT;


//thread error
static thread_local EASYSSL_ERROR thread_error = {0, 0};


//sets the error
static void set_error(int category, int number) {
    thread_error.category = category;
    thread_error.number = number;
}


//sets errno, then the error
static void set_errno(int err) {
    errno = err;
    set_error(EASYSSL_ERROR_SYSTEM, err);
}


//clears all errors
static void clear_errors() {
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
    abort();
}


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


//close a socket handle
static void close_socket(EASYSSL_SOCKET_HANDLE sock) {
#ifdef WIN32
    closesocket(sock);
#else
    close(sock);
#endif
}


//destroy context
static void destroy_context(SSL_CTX* ctx) {
    if (ctx) {
        SSL_CTX_free(ctx);
    }
}


//load the certificates/key for a context
static EASYSSL_BOOL load_security_data(EASYSSL_SECURITY_DATA_STRUCT* sd, SSL_CTX* ctx) {
    //chain file
    if (sd->ca_chain_file && SSL_CTX_use_certificate_chain_file(ctx, sd->ca_chain_file) != 1) {
        goto FAILURE;
    }

    //file
    if (sd->ca_file && SSL_CTX_use_certificate_file(ctx, sd->ca_file, SSL_FILETYPE_PEM) != 1) {
        goto FAILURE;
    }

    //path
    if (sd->ca_path && SSL_CTX_load_verify_dir(ctx, sd->ca_path) != 1) {
        goto FAILURE;
    }

    //store
    if (sd->ca_store && SSL_CTX_load_verify_store(ctx, sd->ca_store) != 1) {
        goto FAILURE;
    }

    //key file
    if (SSL_CTX_use_PrivateKey_file(ctx, sd->key_file, SSL_FILETYPE_PEM) != 1) {
        goto FAILURE;
    }

    //success
    return EASYSSL_TRUE;

    //failure
    FAILURE:
    set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
    return EASYSSL_FALSE;

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

    //success; set the sd member; return the context
    *sd_member = ctx;
    return ctx;
}


//init cookie verify context
static EASYSSL_BOOL init_cookie_verify_context(SSL* ssl, COOKIE_VERIFY_CONTEXT* cookie_verify_context) {
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

    //set cookie verification methods
    SSL_CTX_set_stateless_cookie_generate_cb(result, generate_cookie);
    SSL_CTX_set_stateless_cookie_verify_cb(result, verify_cookie);

    //success
    unlock_mutex(&sd->mutex);
    return result;
}


//tcp accept
static int tcp_accept(EASYSSL_SOCKET sock, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    int r;
    long lr;
    EASYSSL_SOCKET_HANDLE handle;
    SSL* ssl;
    COOKIE_VERIFY_CONTEXT* cookie_verify_context;

    //on first entry, do the initialization of the accept sequence
    if (!sock->retry) {
        //the socket must not have an ssl
        if (sock->ssl) {
            set_errno(EINVAL);
            return EASYSSL_SOCKET_ERROR;
        }

        //create context for tcp if not yet created
        SSL_CTX* ctx = tcp_get_or_create_server_context(sock->security_data);

        //if failed to create context
        if (!ctx) {
            return EASYSSL_SOCKET_ERROR;
        }

        //accept a connection
        int addrlen = sizeof(struct sockaddr_storage);
        handle = accept(sock->handle, &addr->sa, &addrlen);

        //if failed to create a socket
        if (handle < 0) {
            //TODO handle retry at socket level
            handle_socket_error();
            return EASYSSL_SOCKET_ERROR;
        }

        //create the SSL
        ssl = SSL_new(ctx);

        //if failed to create the ssl
        if (!ssl) {
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            close_socket(handle);
            return EASYSSL_SOCKET_ERROR;
        }

        //set the socket handle
        SSL_set_fd(ssl, (int)handle);

        //turn Nagle's algorithm off for the handshake in order to allow ACK to be returned as soon as possible
        char on = 1;
        setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        //init cookie verify context
        cookie_verify_context = (COOKIE_VERIFY_CONTEXT*)malloc(sizeof(COOKIE_VERIFY_CONTEXT));
        if (!init_cookie_verify_context(ssl, cookie_verify_context)) {
            goto FAILURE;
        }

        //in order to find the ssl in the next retry, set the socket's ssl to the new ssl
        sock->ssl = ssl;
    }
    else {
        ssl = sock->ssl;
        handle = SSL_get_fd(ssl);
        cookie_verify_context = SSL_get_app_data(ssl);
    }

    //ssl accept
    r = SSL_accept(ssl);

    int connection_closed = 0;

    //on success, create a new socket
    if (r == 1) {
        //if there is no certificate, fail
        if (!SSL_get0_peer_certificate(ssl)) {
            set_error(EASYSSL_ERROR_EASYSSL, EASYSSL_ERROR_NO_PEER_CERTIFICATE);
            goto FAILURE;
        }

        //if verification failed, fail
        lr = SSL_get_verify_result(ssl);
        if (lr != X509_V_OK) {
            set_error(EASYSSL_ERROR_OPENSSL, lr);
            goto FAILURE;
        }

        EASYSSL_SOCKET_STRUCT* new_sock = (EASYSSL_SOCKET_STRUCT*)malloc(sizeof(EASYSSL_SOCKET_STRUCT));

        //if failed to create a socket
        if (!new_sock) {
            set_error(EASYSSL_ERROR_SYSTEM, errno);
            goto FAILURE;
        }

        //setup the new socket
        new_sock->handle = handle;
        new_sock->security_data = sock->security_data;
        new_sock->ssl = ssl;
        new_sock->type = sock->type;
        new_sock->retry = 0;

        //restore the socket's tcp no delay value
        char off = 0;
        setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &off, sizeof(off));

        //reset the cookie verify data in the ssl
        SSL_set_app_data(ssl, NULL);

        //return the new socket
        *new_socket = new_sock;

        //free the cookie verify context
        free(cookie_verify_context);

        //restore the input socket
        sock->retry = 0;
        sock->ssl = NULL;

        //success
        return EASYSSL_SOCKET_OK;
    }

    //handle error
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
            sock->retry = 1;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_ZERO_RETURN:
            set_error(EASYSSL_ERROR_OPENSSL, SSL_ERROR_ZERO_RETURN);
            connection_closed = 1;
            goto FAILURE;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            sock->retry = 1;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            handle_syscall_error();
            goto FAILURE;

        case SSL_ERROR_SSL:
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            goto FAILURE;
    }

    //should not happen
    abort();

    FAILURE:
    //restore the socket
    sock->ssl = NULL;
    sock->retry = 0;

    //release resources
    close_socket(handle);
    SSL_free(ssl);
    free(cookie_verify_context);

    //closed or failure
    return connection_closed ? EASYSSL_SOCKET_CLOSED : EASYSSL_SOCKET_ERROR;
}


//udp accept
static int udp_accept(EASYSSL_SOCKET sock, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    //TODO
    return 0;
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


//tcp connect
static int tcp_connect(EASYSSL_SOCKET sock, const EASYSSL_SOCKET_ADDRESS* addr) {
    int r;
    long lr;
    SSL* ssl;
    char tcp_nodelay;

    //on first entry
    if (!sock->retry) {
        //the socket must not have an ssl
        if (sock->ssl) {
            set_errno(EINVAL);
            return EASYSSL_SOCKET_ERROR;
        }

        //create context for tcp if not yet created
        SSL_CTX* ctx = tcp_get_or_create_client_context(sock->security_data);

        //if failed to create context
        if (!ctx) {
            return EASYSSL_SOCKET_ERROR;
        }

        //connect the socket
        if (connect(sock->handle, &addr->sa, sizeof(struct sockaddr_storage))) {
            handle_socket_error();
            //TODO handle retry at socket level
            return EASYSSL_SOCKET_ERROR;
        }

        //create the SSL
        ssl = SSL_new(ctx);

        //if failed to create the ssl
        if (!ssl) {
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            return EASYSSL_SOCKET_ERROR;
        }

        //set the socket handle
        SSL_set_fd(ssl, (int)sock->handle);

        //keep the current no delay option of the socket
        int optlen = sizeof(tcp_nodelay);
        getsockopt(sock->handle, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, &optlen);
        SSL_set_app_data(ssl, tcp_nodelay);

        //turn Nagle's algorithm off for the handshake in order to allow ACK to be returned as soon as possible
        char on = 1;
        setsockopt(sock->handle, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

        //store the ssl in the socket 
        sock->ssl = ssl;
    }
    else {
        ssl = sock->ssl;
        tcp_nodelay = (char)SSL_get_app_data(ssl);
    }

    //ssl connect
    r = SSL_connect(ssl);

    int connection_closed = 0;

    //on success
    if (r == 1) {
        //if there is no certificate, fail
        if (!SSL_get0_peer_certificate(ssl)) {
            set_error(EASYSSL_ERROR_EASYSSL, EASYSSL_ERROR_NO_PEER_CERTIFICATE);
            goto FAILURE;
        }

        //if verification failed, fail
        lr = SSL_get_verify_result(ssl);
        if (lr != X509_V_OK) {
            set_error(EASYSSL_ERROR_OPENSSL, lr);
            goto FAILURE;
        }

        //success; restore the no delay parameter
        setsockopt(sock->handle, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));

        //restore the socket
        sock->retry = 0;

        return EASYSSL_SOCKET_OK;
    }

    //handle error
    switch (SSL_get_error(ssl, r)) {
        case SSL_ERROR_NONE:
            sock->retry = 1;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_ZERO_RETURN:
            set_error(EASYSSL_ERROR_OPENSSL, SSL_ERROR_ZERO_RETURN);
            connection_closed = 1;
            goto FAILURE;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            sock->retry = 1;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            handle_syscall_error();
            goto FAILURE;

        case SSL_ERROR_SSL:
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            goto FAILURE;
    }

    //should not happen
    abort();

    FAILURE:
    SSL_free(ssl);
    sock->ssl = NULL;
    sock->retry = 0;
    return connection_closed ? EASYSSL_SOCKET_CLOSED : EASYSSL_SOCKET_ERROR;
}


//udp connect
static EASYSSL_BOOL udp_connect(EASYSSL_SOCKET socket, const EASYSSL_SOCKET_ADDRESS* addr) {
    //TODO
    return EASYSSL_TRUE;
}


//set socket blocking
static EASYSSL_BOOL set_socket_blocking(EASYSSL_SOCKET_HANDLE socket, EASYSSL_BOOL blocking) {
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


//init
EASYSSL_BOOL EASYSSL_init() {
#ifdef _WIN32
    WSADATA wsadata;
    int r = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (r) {
        set_error(EASYSSL_ERROR_WINSOCK, WSAGetLastError());
        return EASYSSL_FALSE;
    }
#endif
    return EASYSSL_TRUE;
}


//cleanup
EASYSSL_BOOL EASYSSL_cleanup() {
#ifdef _WIN32
    int r = WSACleanup();
    if (r) {
        set_error(EASYSSL_ERROR_WINSOCK, WSAGetLastError());
        return EASYSSL_FALSE;
    }
#endif
    return EASYSSL_TRUE;
}


//create security data
EASYSSL_SECURITY_DATA EASYSSL_create_security_data(const char* ca_path, const char* ca_file, const char* ca_store, const char* ca_chain_file, const char* key_file) {
    EASYSSL_SECURITY_DATA_STRUCT* sd;

    //allocate sd
    sd = (EASYSSL_SECURITY_DATA_STRUCT*)malloc(sizeof(EASYSSL_SECURITY_DATA_STRUCT));

    //handle allocation failure
    if (!sd) {
        set_error(EASYSSL_ERROR_SYSTEM, errno);
        return NULL;
    }

    //copy the strings
    int ok = 1;
    ok &= copy_string(&sd->ca_path, ca_path);
    ok &= copy_string(&sd->ca_file, ca_file);
    ok &= copy_string(&sd->ca_store, ca_store);
    ok &= copy_string(&sd->ca_chain_file, ca_chain_file);
    ok &= copy_string(&sd->key_file, key_file);

    //if there was a string copy failure
    if (!ok) {
        free(sd->ca_path);
        free(sd->ca_file);
        free(sd->ca_store);
        free(sd->ca_chain_file);
        free(sd->key_file);
        free(sd);
        return NULL;
    }

    //init other fields
    init_mutex(&sd->mutex);
    sd->tcp_server_ctx = NULL;
    sd->udp_server_ctx = NULL;
    sd->tcp_client_ctx = NULL;
    sd->udp_client_ctx = NULL;

    //success
    return sd;
}



//destroy security data
EASYSSL_BOOL EASYSSL_destroy_security_data(EASYSSL_SECURITY_DATA sd) {
    //check param
    if (!sd) {
        set_errno(EINVAL);
        return EASYSSL_FALSE;
    }

    //destroy contexts
    destroy_context(sd->tcp_server_ctx);
    destroy_context(sd->tcp_client_ctx);
    destroy_context(sd->udp_server_ctx);
    destroy_context(sd->udp_client_ctx);

    //free resources
    destroy_mutex(&sd->mutex);
    free(sd->ca_path);
    free(sd->ca_file);
    free(sd->ca_store);
    free(sd->ca_chain_file);
    free(sd->key_file);
    free(sd);

    //success
    return EASYSSL_TRUE;
}


//create socket
EASYSSL_SOCKET EASYSSL_socket(EASYSSL_SECURITY_DATA sd, int af, int st, int p, EASYSSL_BOOL blocking) {
    EASYSSL_SOCKET_STRUCT* sock;

    //check params
    if (!sd || (st != SOCK_STREAM && st != SOCK_DGRAM)) {
        set_errno(EINVAL);
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
    sock->type = st == SOCK_STREAM;
    sock->retry = 0;

    //success
    return sock;
}


//get handle
EASYSSL_SOCKET_HANDLE EASYSSL_get_socket_handle(EASYSSL_SOCKET socket) {
    //check param
    if (!socket) {
        set_errno(EINVAL);
        return EASYSSL_INVALID_SOCKET_HANDLE;
    }

    //return handle
    return socket->handle;
}


//shutdown socket
EASYSSL_BOOL EASYSSL_shutdown(EASYSSL_SOCKET socket) {
    //check param
    if (!socket) {
        set_errno(EINVAL);
        return EASYSSL_SOCKET_ERROR;
    }

    //if no ssl, there is nothing to shutdown
    if (!socket->ssl) {
        return EASYSSL_SOCKET_OK;
    }

    //clear errors, in order to later find out which error mechanism was used
    clear_errors();

    //if already shutdown
    if (SSL_get_shutdown(socket->ssl)) {
        return EASYSSL_SOCKET_OK;
    }

    //shutdown or read
    int r;    
    if (socket->retry) {
        char buf[1];
        r = SSL_read(socket->ssl, buf, sizeof(buf));
    }
    else {
        r = SSL_shutdown(socket->ssl);
    }

    //handle error
    switch (SSL_get_error(socket->ssl, r)) {
        case SSL_ERROR_NONE:
            socket->retry = 0;
            return EASYSSL_SOCKET_OK;

        case SSL_ERROR_ZERO_RETURN:
            socket->retry = 0;
            return EASYSSL_SOCKET_CLOSED;

        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_CONNECT:
        case SSL_ERROR_WANT_ACCEPT:
        case SSL_ERROR_WANT_X509_LOOKUP:
        case SSL_ERROR_WANT_ASYNC:
        case SSL_ERROR_WANT_ASYNC_JOB:
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            socket->retry = 1;
            return EASYSSL_SOCKET_RETRY;

        case SSL_ERROR_SYSCALL:
            socket->retry = 0;
            handle_syscall_error();
            return EASYSSL_SOCKET_ERROR;

        case SSL_ERROR_SSL:
            socket->retry = 0;
            set_error(EASYSSL_ERROR_OPENSSL, ERR_get_error());
            return EASYSSL_SOCKET_ERROR;
    }

    //unhandled case; normally this should not happen
    abort();
}


//destroy a socket
EASYSSL_BOOL EASYSSL_close(EASYSSL_SOCKET socket) {
    //shutdown the socket
    if (!EASYSSL_shutdown(socket)) {
        return EASYSSL_FALSE;
    }

    //free its ssl part
    if (socket->ssl) {
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
    if (!socket || addr) {
        set_errno(EINVAL);
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
        set_errno(EINVAL);
        return EASYSSL_FALSE;
    }

    //handle socket type
    switch (socket->type) {
        case SOCK_STREAM:
            if (listen(socket->handle, backlog)) {
                handle_socket_error();
                return EASYSSL_FALSE;
            }
            break;

        case SOCK_DGRAM:
            //nothing at the moment
            break; 

        default:
            set_errno(EINVAL);
            return EASYSSL_FALSE;
    }

    //success
    return EASYSSL_TRUE;
}


//accept connection
int EASYSSL_accept(EASYSSL_SOCKET socket, EASYSSL_SOCKET* new_socket, EASYSSL_SOCKET_ADDRESS* addr) {
    //check param
    if (!socket) {
        set_errno(EINVAL);
        return EASYSSL_SOCKET_ERROR;
    }

    //handle socket type
    switch (socket->type) {
        case SOCK_STREAM:
            return tcp_accept(socket, new_socket, addr);

        case SOCK_DGRAM:
            return udp_accept(socket, new_socket, addr);

        default:
            set_errno(EINVAL);
            return EASYSSL_SOCKET_ERROR;
    }

    //should not happen
    abort();
}


//connect
int EASYSSL_connect(EASYSSL_SOCKET socket, const EASYSSL_SOCKET_ADDRESS* addr) {
    //check param
    if (!socket || !addr) {
        set_errno(EINVAL);
        return EASYSSL_SOCKET_ERROR;
    }

    //handle socket type
    switch (socket->type) {
        case SOCK_STREAM:
            return tcp_connect(socket, addr);

        case SOCK_DGRAM:
            return udp_connect(socket, addr);

        default:
            set_errno(EINVAL);
            return EASYSSL_SOCKET_ERROR;
    }

    //should not happen
    abort();
}


//send data
int EASYSSL_send(EASYSSL_SOCKET socket, const void* buffer, int buffer_size) {
    int r;

    //check param
    if (!socket || !socket->ssl || buffer_size <= 0) {
        set_errno(EINVAL);
        return -1;
    }

    //write data
    r = SSL_write(socket->ssl, buffer, buffer_size);

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

    //should not happen
    abort();
}


//receive data
int EASYSSL_recv(EASYSSL_SOCKET socket, void* buffer, int buffer_size) {
    int r;

    //check param
    if (!socket || !socket->ssl || buffer_size <= 0) {
        set_errno(EINVAL);
        return -1;
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

    //should not happen
    abort();
}



//get socket option
EASYSSL_BOOL EASYSSL_getsockopt(EASYSSL_SOCKET socket, int level, int name, void* opt, int len) {
    //check param
    if (!socket) {
        set_errno(EINVAL);
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
        set_errno(EINVAL);
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
        set_errno(EINVAL);
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
        set_errno(EINVAL);
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
    //check params
    if (!error || !buffer || buffer_size <= 0) {
        set_errno(EINVAL);
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
        case EASYSSL_ERROR_WINSOCK:
            return FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error->number, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, buffer_size, NULL) > 0;
#endif

        case EASYSSL_ERROR_OPENSSL:
            buffer[0] = '\0';
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
    return EASYSSL_FALSE;
}
