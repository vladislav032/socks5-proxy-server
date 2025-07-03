#ifndef CLIENT_CONTEXT_H
#define CLIENT_CONTEXT_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

#define BUFFER_SIZE 4096

enum class ProxyState {
    Handshake,
    Request,
    Connecting,
    Established,
    Error
};

class Socks5Proxy;

struct ClientContext {
    SOCKET clientSocket;
    SOCKET remoteSocket;
    ProxyState state;
    char clientBuffer[BUFFER_SIZE];
    char remoteBuffer[BUFFER_SIZE];
    int bytesTransferred;
    OVERLAPPED clientOverlapped;
    OVERLAPPED remoteOverlapped;
    WSABUF clientWsaBuf;
    WSABUF remoteWsaBuf;
    sockaddr_in clientAddr;
    char clientIP[INET_ADDRSTRLEN];
    std::string remoteHost;
    unsigned short remotePort;
    bool clientPending;
    bool remotePending;
    ULONGLONG lastActivityTime;
    char acceptBuffer[(sizeof(sockaddr_in) + 16) * 2];
    Socks5Proxy* proxy;

    explicit ClientContext(Socks5Proxy* proxy);
    ~ClientContext();

private:
    void Initialize();
};

#endif // CLIENT_CONTEXT_H