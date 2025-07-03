#include "client_context.h"
#include "socks5_proxy.h"
#include <stdexcept>

#define BUFFER_SIZE 4096

ClientContext::ClientContext(Socks5Proxy* proxy) : proxy(proxy) {
    if (!proxy) {
        throw std::invalid_argument("Proxy pointer cannot be null");
    }

    clientSocket = INVALID_SOCKET;
    remoteSocket = INVALID_SOCKET;
    state = ProxyState::Handshake;
    bytesTransferred = 0;
    memset(clientBuffer, 0, BUFFER_SIZE);
    memset(remoteBuffer, 0, BUFFER_SIZE);
    memset(&clientOverlapped, 0, sizeof(OVERLAPPED));
    memset(&remoteOverlapped, 0, sizeof(OVERLAPPED));
    clientWsaBuf.buf = clientBuffer;
    clientWsaBuf.len = BUFFER_SIZE;
    remoteWsaBuf.buf = remoteBuffer;
    remoteWsaBuf.len = BUFFER_SIZE;
    memset(&clientAddr, 0, sizeof(sockaddr_in));
    memset(clientIP, 0, INET_ADDRSTRLEN);
    remotePort = 0;
    clientPending = false;
    remotePending = false;
    lastActivityTime = GetTickCount64();
    memset(acceptBuffer, 0, sizeof(acceptBuffer));
}

ClientContext::~ClientContext() {
    if (clientSocket != INVALID_SOCKET) {
        closesocket(clientSocket);
        clientSocket = INVALID_SOCKET;
    }
    if (remoteSocket != INVALID_SOCKET) {
        closesocket(remoteSocket);
        remoteSocket = INVALID_SOCKET;
    }
    if (proxy) {
        proxy->DecrementConnectionCount();
        proxy = nullptr;
    }
}