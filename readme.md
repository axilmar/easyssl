# EasySSL

A C/C++ library for making using secure sockets easy.

Using secure sockets in C/C++, especially for new comers, is notoriously hard, and the lack of working examples that cover the most often used cases is phenomenal.

Documentation is hard to read as the authors, which are very knowledgeable on what they are doing, 'compress' their knowledge in a few short sentences on each topic, making it really hard for amateurs to follow the documentation.

This library aims to provide an API which makes it easy for C or C++ programmers to use secure sockets, by mimicking the Berkeley sockets API, with a few twists.

It uses the most popular of the open source ssl libraries, OpenSSL.

Let's see some examples...

## Example in C

#### Client

```c
//master header
#include "easyssl.h"

int main() {
    //init openssl, logging, networking etc
    EASYSSL_init();
    
    //create a 'security data' object which holds the certificates and the keys
    EASYSSL_SECURITY_DATA sd = EASYSSL_create_security_data();
    
    //load some certificates and keys
    EASYSSL_add_certificate_file(sd, "client_cert.pem");
    EASYSSL_add_private_key_file(sd, "client_key.pem");
    
    //create a blocking secure socket
    EASYSSL_SOCKET socket = EASYSSL_socket(sd, AF_INET, SOCK_STREAM, 0, EASYSSL_TRUE);
    
    //prepare a socket address for connecting to the server
    EASYSSL_SOCKET_ADDRESS server_addr;
    server_addr.sa4.sin_family = AF_INET;
    server_addr.sa4.sin_addr = INADDR_LOOPBACK;
    server_addr.sa4.sin_port = htons(10000);
    
    //connect to the server
    EASYSSL_connect(socket, &server_addr);
    
    //send a message to the server
    const char msg[] = "Hello server!";
    int bytes_sent = EASYSSL_send(socket, msg, sizeof(msg));
    
    //wait for reply from server
    char reply[100];
    int bytes_received = EASYSSL_recv(socket, reply, sizeof(reply));
    
    //destroy the secure socket
    EASYSSL_close(socket);
    
    //destroy the security data
    EASYSSL_destroy_security_data(sd);
    
    //cleanup
    EASYSSL_cleanup();
}
```

The important points in the above code are the following:

- the procedure to connect to a server is the exact same as in Berkeley sockets, for a client:
  - create socket
  - connect to server
  - send/receive messages
  - close socket
- differences from using unsecure sockets:
  - an object that holds the certificates and keys must be created before creating any sockets (the security data object).
  - the socket functions are slightly different:
    - function `EASYSSL_socket` accepts a security data object and a blocking boolean parameter; it can be used to create non-blocking sockets.
    - function `EASYSSL_connect` uses a socket address union type, in order to avoid all those nasty casts from `sockaddr_in*` to `sockaddr*`.
    - functions `EASYSSL_send` and `EASYSSL_recv` do not allow the specification of any flags for sending/receiving; not important since few flags are common between systems and they are rarely used (personally  I never used them in 20+ years of socket programming!). 
- SSL details:
  - handshake is done behind the scenes.

#### Server

```c
//master header
#include "easyssl.h"

int main() {
    //init openssl, logging, networking etc
    EASYSSL_init();
    
    //create a 'security data' object which holds the certificates and the keys
    EASYSSL_SECURITY_DATA sd = EASYSSL_create_security_data();
    
    //load some certificates and keys
    EASYSSL_add_certificate_file(sd, "server_cert.pem");
    EASYSSL_add_private_key_file(sd, "server_key.pem");
    
    //create a blocking secure socket
    EASYSSL_SOCKET socket = EASYSSL_socket(sd, AF_INET, SOCK_STREAM, 0, EASYSSL_TRUE);
    
    //bind the socket
    EASYSSL_SOCKET_ADDRESS server_addr;
    server_addr.sa4.sin_family = AF_INET;
    server_addr.sa4.sin_addr = INADDR_LOOPBACK;
    server_addr.sa4.sin_port = htons(10000);
    EASYSSL_bind(socket, &server_addr);
    
    //put the socket in listening mode
    EASYSSL_listen(socket, SOMAXCONN);
    
    //accept connection
    EASYSSL_SOCKET client_socket;
    EASYSSL_SOCKET_ADDRESS client_addr;
    EASYSSL_accept(socket, &client_socket, &client_addr);
    
    //receive data
    char msg[100];
    EASYSSL_recv(client_socket, msg, sizeof(msg));
    
    //send reply
    char reply[] = "Hello client!";
    EASYSSL_send(client_socket, reply, sizeof(reply));
    
    //destroy the secure sockets
    EASYSSL_close(client_socket);
    EASYSSL_close(socket);
    
    //destroy the security data
    EASYSSL_destroy_security_data(sd);
    
    //cleanup
    EASYSSL_cleanup();
}
```

The important points in the above code are the following:

- the procedure to accept connections from clients is the exact same as in Berkeley sockets:
  - create socket
  - bind socket
  - put socket in listening mode
  - accept connection to create client socket
  - send/receive messages
  - close sockets
- differences from using unsecure sockets:
  - an object that holds the certificates and keys must be created before creating any sockets (the security data object).
  - the socket functions are slightly different:
    - function `EASYSSL_accept` returns the created socket through a function argument and not as a result; this is necessary because the accept function can return a variety of socket status codes which are not to be mixed with the created socket. 
- SSL details:
  - handshake and verification is done behind the scenes.

## Example in C++

Here are the above examples in C++:

#### Client

```c++
#include <string>
#include "easyssl.hpp"
using namespace std;
using namespace easyssl;

int main() {
    //security data
    security_data sd;
    sd.add_certificate_file("client_cert.pem");
    sd.add_private_key_file("client_key.pem");
    
    //socket
    socket sock(sd, AF_INET, SOCK_STREAM, 0);
    
    //connect to server
    socket_address server_addr(INADDR_LOOPBACK, 10000);
    sock.connect(server_addr);
    
    //send message
    string msg = "hello server!";
    sock.send(msg.data(), msg.size());
    
    string reply(100);
    sock.receive(reply.data(), reply.size());
}
```

The C++ part of the library takes full advantage of RAII, and therefore there is no need to initialize the library and cleanup resources.

#### Server

```c++
#include <string>
#include "easyssl.hpp"
using namespace std;
using namespace easyssl;

int main() {
    //security data
    security_data sd;
    sd.add_certificate_file("server_cert.pem");
    sd.add_private_key_file("server_key.pem");
    
    //socket
    socket sock(sd, AF_INET, SOCK_STREAM, 0);
    
    //bind socket
    socket_address server_addr(INADDR_LOOPBACK, 10000);
    sock.bind(server_addr);
    
    //put socket in listening mode
    sock.listen();
    
    //accept connection
    socket client_sock;
    socket_address client_addr;
    sock.accept(client_sock, client_addr);
    
    //receive message
    string msg(100);
    sock.receive(msg.data(), msg.size());
    
    //send reply
    string reply = "hello client!";
    sock.receive(reply.data(), reply.size());
}
```

## Blocking vs non-blocking sockets

The function `EASYSSL_socket` has the following signature:

```c
EASYSSL_SOCKET EASYSSL_socket(EASYSSL_SECURITY_DATA security_data, int address_family, int socket_type, int protocol, EASYSSL_BOOL blocking);
```

The last parameter defines if a socket is created as blocking or non-blocking.

### Blocking sockets blocking functions

A blocking socket blocks the execution of the current thread in the following functions:

- shutdown
- accept
- connect
- recv
- close

### Non-blocking sockets blocking functions

A non-blocking socket blocks the execution of the current thread in the following functions:

- close 

### Handling non-blocking socket operations

In order to handle non-blocking sockets, the enumeration `EASYSSL_SOCKET_STATUS` provides the following values:

- `EASYSSL_SOCKET_CLOSED`: the connection is closed by the peer or the socket handle is no longer valid.
- `EASYSSL_SOCKET_RETRY`: the operation needs to be retried.
- `EASYSSL_SOCKET_CONNECTION_REFUSED`: connection refused by peer.
- `EASYSSL_SOCKET_ERROR`: there was an error.
- `EASYSSL_SOCKET_SUCCESS`: the operation was successful.

For example, connecting a non-blocking socket can be written like this:

```c
CONNECT:
switch (EASYSSL_connect(socket, &addr)) {
    case EASYSSL_SOCKET_CLOSED:
        printf("Socket is closed\n");
        break;
        
    case EASY_SSL_SOCKET_RETRY:
        wait_for_retry();
        goto CONNECT;
        
    case EASY_SSL_SOCKET_CONNECTION_REFUSED:
        printf("Connection refused\n");
        break;
        
    case EASYSSL_SOCKET_ERROR:
        printf("There was an error.\n");
        break;
        
    case EASYSSL_SOCKET_SUCCESS:
        printf("Connected\n");
        break;
}
```

### Using poll/select with sockets

Poll/select (or other, e.g. epoll) can be used to poll a socket.

The function `EASYSSL_get_socket_handle` returns the socket's native handle, which can then be used for polling.

## Error handling

The function `EASYSSL_get_last_error` returns a pointer to the current thread's last error.

The struct `EASYSSL_ERROR` has the following form:

```c
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
```

The error category enumeration is the following:

```c
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
```

The `number` field of the `EASYSSL_ERROR` structure depends on the error category.

In C++, the class `easyssl::error`, derived from `struct EASYSSL_ERROR`, is thrown when there is an error.

