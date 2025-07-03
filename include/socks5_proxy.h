#ifndef SOCKS5_PROXY_H
#define SOCKS5_PROXY_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <atomic>
#include <string>
#include "client_context.h"

#define PROXY_PORT 1080
#define CONNECT_TIMEOUT 60000
#define MAX_PENDING_ACCEPTS 5
#define MAX_CONCURRENT_CONNECTIONS 1000
#define CONNECTION_TIMEOUT 600000

typedef BOOL(WINAPI* LPFN_ACCEPTEX)(
    SOCKET sListenSocket,
    SOCKET sAcceptSocket,
    PVOID lpOutputBuffer,
    DWORD dwReceiveDataLength,
    DWORD dwLocalAddressLength,
    DWORD dwRemoteAddressLength,
    LPDWORD lpdwBytesReceived,
    LPOVERLAPPED lpOverlapped);

typedef BOOL(WINAPI* LPFN_CONNECTEX)(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped);

class Socks5Proxy {
public:
    Socks5Proxy();
    ~Socks5Proxy();

    bool Initialize();
    void Run();

    void IncrementConnectionCount();
    void DecrementConnectionCount();

private:
    HANDLE iocpHandle;
    SOCKET listenSocket;
    std::atomic<int> pendingAccepts;
    std::atomic<int> activeConnections;
    LPFN_ACCEPTEX AcceptExPtr;
    LPFN_CONNECTEX ConnectExPtr;

    void PrintTimestamp();
    void StartAccept();
    void SafeDelete(ClientContext* context);
    void ProcessNewConnection(ClientContext* context);
    void ProcessClientOperation(ClientContext* context, LPOVERLAPPED overlapped);
    void HandleHandshake(ClientContext* context);
    void HandleRequest(ClientContext* context);
    void HandleTCPConnect(ClientContext* context);
    void HandleConnectionCompletion(ClientContext* context);
    void SendSuccessResponse(ClientContext* context);
    void HandleDataTransfer(ClientContext* context, LPOVERLAPPED overlapped);
    void StartReceive(ClientContext* context, bool fromClient);
};

#endif // SOCKS5_PROXY_H