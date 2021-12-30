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

(the following content is to be written in the near future)

Non-blocking sockets in C

Non-blocking sockets in C++

Error handling in C

Error Handling in C++

