#include "socks5_proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <memory>
#include <unordered_map>
#include <sstream>
#include <time.h>
#include <algorithm>
#include <stdexcept>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

Socks5Proxy::Socks5Proxy() :
    iocpHandle(INVALID_HANDLE_VALUE),
    listenSocket(INVALID_SOCKET),
    pendingAccepts(0),
    activeConnections(0),
    AcceptExPtr(nullptr),
    ConnectExPtr(nullptr) {
}

Socks5Proxy::~Socks5Proxy() {
    if (listenSocket != INVALID_SOCKET) {
        closesocket(listenSocket);
    }
    if (iocpHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(iocpHandle);
    }
    WSACleanup();
}

bool Socks5Proxy::Initialize() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return false;
    }

    listenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (listenSocket == INVALID_SOCKET) {
        printf("WSASocket failed: %d\n", WSAGetLastError());
        return false;
    }

    GUID guidAcceptEx = WSAID_ACCEPTEX;
    GUID guidConnectEx = WSAID_CONNECTEX;
    DWORD bytesReturned;

    if (WSAIoctl(listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidAcceptEx, sizeof(guidAcceptEx),
        &AcceptExPtr, sizeof(AcceptExPtr),
        &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
        printf("WSAIoctl for AcceptEx failed: %d\n", WSAGetLastError());
        return false;
    }

    if (WSAIoctl(listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guidConnectEx, sizeof(guidConnectEx),
        &ConnectExPtr, sizeof(ConnectExPtr),
        &bytesReturned, NULL, NULL) == SOCKET_ERROR) {
        printf("WSAIoctl for ConnectEx failed: %d\n", WSAGetLastError());
        return false;
    }

    int reuse = 1;
    if (setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse)) == SOCKET_ERROR) {
        printf("setsockopt failed: %d\n", WSAGetLastError());
        return false;
    }

    int keepAlive = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepAlive, sizeof(keepAlive));

    sockaddr_in serverAddr = { 0 };
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PROXY_PORT);

    if (bind(listenSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        return false;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        return false;
    }

    iocpHandle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (iocpHandle == NULL) {
        printf("CreateIoCompletionPort failed: %d\n", GetLastError());
        return false;
    }

    if (CreateIoCompletionPort((HANDLE)listenSocket, iocpHandle, (ULONG_PTR)this, 0) == NULL) {
        printf("CreateIoCompletionPort for listen socket failed: %d\n", GetLastError());
        return false;
    }

    printf("[+] SOCKS5 proxy server started on port %d\n", PROXY_PORT);
    printf("[+] Waiting for connections...\n");
    return true;
}

void Socks5Proxy::SafeDelete(ClientContext* context) {
    if (!context) return;
    if (!context->clientPending && !context->remotePending) {
        delete context;
    }
}

void Socks5Proxy::IncrementConnectionCount() { activeConnections++; }
void Socks5Proxy::DecrementConnectionCount() { activeConnections--; }

void Socks5Proxy::PrintTimestamp() {
    time_t now = time(0);
    struct tm tm;
    localtime_s(&tm, &now);
    char buf[80];
    strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S]", &tm);
    printf("%s ", buf);
}

void Socks5Proxy::StartAccept() {
    if (pendingAccepts >= MAX_PENDING_ACCEPTS) {
        return;
    }

    SOCKET clientSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (clientSocket == INVALID_SOCKET) {
        printf("[!] WSASocket failed: %d\n", WSAGetLastError());
        return;
    }

    ClientContext* context = new (std::nothrow) ClientContext(this);
    if (!context) {
        printf("[!] Failed to allocate client context\n");
        closesocket(clientSocket);
        return;
    }

    context->clientSocket = clientSocket;
    pendingAccepts++;

    DWORD bytesReceived = 0;
    if (!AcceptExPtr(
        listenSocket,
        clientSocket,
        context->acceptBuffer,
        0,
        sizeof(sockaddr_in) + 16,
        sizeof(sockaddr_in) + 16,
        &bytesReceived,
        &context->clientOverlapped)) {

        int error = WSAGetLastError();
        if (error != ERROR_IO_PENDING) {
            printf("[!] AcceptEx failed: %d\n", error);
            closesocket(clientSocket);
            SafeDelete(context);
            pendingAccepts--;
            return;
        }
    }
}

void Socks5Proxy::ProcessNewConnection(ClientContext* context) {
    if (!context) {
        return;
    }

    pendingAccepts--;

    if (activeConnections >= MAX_CONCURRENT_CONNECTIONS) {
        printf("[-] Connection limit reached, rejecting connection\n");
        SafeDelete(context);
        return;
    }

    activeConnections++;

    if (CreateIoCompletionPort((HANDLE)context->clientSocket, iocpHandle, (ULONG_PTR)context, 0) == NULL) {
        printf("CreateIoCompletionPort failed: %d\n", GetLastError());
        SafeDelete(context);
        return;
    }

    if (setsockopt(context->clientSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
        (char*)&listenSocket, sizeof(listenSocket)) == SOCKET_ERROR) {
        printf("setsockopt failed: %d\n", WSAGetLastError());
    }

    int keepAlive = 1;
    setsockopt(context->clientSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepAlive, sizeof(keepAlive));

    int addrLen = sizeof(context->clientAddr);
    if (getpeername(context->clientSocket, (sockaddr*)&context->clientAddr, &addrLen) == 0) {
        inet_ntop(AF_INET, &context->clientAddr.sin_addr, context->clientIP, INET_ADDRSTRLEN);
    }
    else {
        strcpy_s(context->clientIP, "unknown");
    }

    printf("[+] New client connected from %s\n", context->clientIP);

    DWORD timeout = CONNECT_TIMEOUT;
    setsockopt(context->clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(context->clientSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    StartReceive(context, true);
}

void Socks5Proxy::ProcessClientOperation(ClientContext* context, LPOVERLAPPED overlapped) {
    if (!context) return;

    if (overlapped == &context->clientOverlapped) {
        context->clientPending = false;
    }
    else if (overlapped == &context->remoteOverlapped) {
        context->remotePending = false;
    }

    if (context->bytesTransferred == 0) {
        if (context->state == ProxyState::Connecting) {
            HandleConnectionCompletion(context);
            return;
        }
        if (context->state == ProxyState::Established) {
            printf("[-] Connection closed by %s\n",
                (overlapped == &context->clientOverlapped) ? "client" : "remote");
            closesocket(context->clientSocket);
            closesocket(context->remoteSocket);
            context->clientSocket = INVALID_SOCKET;
            context->remoteSocket = INVALID_SOCKET;
            if (!context->clientPending && !context->remotePending) {
                SafeDelete(context);
            }
            return;
        }
    }

    try {
        switch (context->state) {
        case ProxyState::Handshake:
            HandleHandshake(context);
            break;
        case ProxyState::Request:
            HandleRequest(context);
            break;
        case ProxyState::Connecting:
            break;
        case ProxyState::Established:
            HandleDataTransfer(context, overlapped);

            if (overlapped == &context->clientOverlapped && !context->clientPending) {
                StartReceive(context, true);
            }
            else if (overlapped == &context->remoteOverlapped && !context->remotePending) {
                StartReceive(context, false);
            }
            break;
        default:
            printf("[-] Invalid state for connection\n");
            closesocket(context->clientSocket);
            closesocket(context->remoteSocket);
            context->clientSocket = INVALID_SOCKET;
            context->remoteSocket = INVALID_SOCKET;
            if (!context->clientPending && !context->remotePending) {
                SafeDelete(context);
            }
            break;
        }
    }
    catch (...) {
        printf("[-] Exception processing operation\n");
        closesocket(context->clientSocket);
        closesocket(context->remoteSocket);
        context->clientSocket = INVALID_SOCKET;
        context->remoteSocket = INVALID_SOCKET;
        if (!context->clientPending && !context->remotePending) {
            SafeDelete(context);
        }
    }
}

void Socks5Proxy::HandleHandshake(ClientContext* context) {
    if (context->bytesTransferred < 3) {
        printf("[-] Invalid handshake packet size (%d bytes)\n", context->bytesTransferred);
        SafeDelete(context);
        return;
    }

    if (context->clientBuffer[0] != 0x05) {
        printf("[-] Unsupported SOCKS version (%d)\n", context->clientBuffer[0]);
        SafeDelete(context);
        return;
    }

    int nmethods = static_cast<unsigned char>(context->clientBuffer[1]);
    if (nmethods == 0 || context->bytesTransferred != 2 + nmethods) {
        printf("[-] Invalid methods count (%d)\n", nmethods);
        SafeDelete(context);
        return;
    }

    bool noAuthSupported = false;
    for (int i = 0; i < nmethods; i++) {
        if (context->clientBuffer[2 + i] == 0x00) {
            noAuthSupported = true;
            break;
        }
    }

    if (!noAuthSupported) {
        printf("[-] No supported auth methods\n");
        char response[] = { 0x05, 0xFF };
        send(context->clientSocket, response, sizeof(response), 0);
        SafeDelete(context);
        return;
    }

    char response[] = { 0x05, 0x00 };
    if (send(context->clientSocket, response, sizeof(response), 0) == SOCKET_ERROR) {
        printf("[-] Failed to send handshake response: %d\n", WSAGetLastError());
        SafeDelete(context);
        return;
    }

    context->state = ProxyState::Request;
    StartReceive(context, true);
}

void Socks5Proxy::HandleRequest(ClientContext* context) {
    if (context->bytesTransferred < 4) {
        printf("[-] Invalid request packet\n");
        SafeDelete(context);
        return;
    }

    if (context->clientBuffer[0] != 0x05) {
        printf("[-] Invalid SOCKS version in request\n");
        SafeDelete(context);
        return;
    }

    unsigned char cmd = context->clientBuffer[1];
    printf("[SOCKS5] Command received: 0x%02X from %s\n", cmd, context->clientIP);

    if (cmd == 0x01) {
        HandleTCPConnect(context);
    }
    else {
        printf("[-] Unsupported command: 0x%02X\n", cmd);
        char response[] = { 0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        send(context->clientSocket, response, sizeof(response), 0);
        SafeDelete(context);
    }
}

void Socks5Proxy::HandleTCPConnect(ClientContext* context) {
    printf("[~] TCP CONNECT requested from %s\n", context->clientIP);

    unsigned char addressType = context->clientBuffer[3];
    std::string remoteAddress;
    unsigned short remotePort = 0;
    size_t minSize = 0;

    switch (addressType) {
    case 0x01:
        minSize = 10;
        if (context->bytesTransferred < minSize) {
            printf("[-] Invalid IPv4 request\n");
            SafeDelete(context);
            return;
        }
        {
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &context->clientBuffer[4], ip, INET_ADDRSTRLEN);
            remoteAddress = ip;
            remotePort = ntohs(*(unsigned short*)&context->clientBuffer[8]);
        }
        break;

    case 0x03:
        if (context->bytesTransferred < 5) {
            printf("[-] Invalid domain request\n");
            SafeDelete(context);
            return;
        }
        {
            unsigned char domainLength = static_cast<unsigned char>(context->clientBuffer[4]);
            minSize = 7 + domainLength;
            if (context->bytesTransferred < minSize) {
                printf("[-] Invalid domain request size\n");
                SafeDelete(context);
                return;
            }
            remoteAddress.assign(&context->clientBuffer[5], domainLength);
            remotePort = ntohs(*(unsigned short*)&context->clientBuffer[5 + domainLength]);
        }
        break;

    default:
        printf("[-] Unsupported address type: 0x%02X\n", addressType);
        char response[] = { 0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        send(context->clientSocket, response, sizeof(response), 0);
        SafeDelete(context);
        return;
    }

    context->remoteHost = remoteAddress;
    context->remotePort = remotePort;

    printf("[~] %s is connecting via TCP to %s:%d\n",
        context->clientIP, remoteAddress.c_str(), remotePort);

    context->remoteSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
    if (context->remoteSocket == INVALID_SOCKET) {
        printf("[-] TCP socket creation failed: %d\n", WSAGetLastError());
        char response[] = { 0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        send(context->clientSocket, response, sizeof(response), 0);
        SafeDelete(context);
        return;
    }

    DWORD timeout = CONNECT_TIMEOUT;
    setsockopt(context->remoteSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    setsockopt(context->remoteSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout, sizeof(timeout));

    int keepAlive = 1;
    setsockopt(context->remoteSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepAlive, sizeof(keepAlive));

    if (CreateIoCompletionPort((HANDLE)context->remoteSocket, iocpHandle, (ULONG_PTR)context, 0) == NULL) {
        printf("[-] Failed to associate TCP socket with IOCP: %d\n", GetLastError());
        SafeDelete(context);
        return;
    }

    sockaddr_in localAddr = { 0 };
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = INADDR_ANY;
    localAddr.sin_port = 0;

    if (bind(context->remoteSocket, (sockaddr*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
        printf("[-] Bind failed for TCP socket: %d\n", WSAGetLastError());
        SafeDelete(context);
        return;
    }

    sockaddr_in remoteAddr = { 0 };
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_port = htons(remotePort);

    if (addressType == 0x03) {
        addrinfo hints = { 0 };
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* result = nullptr;

        if (getaddrinfo(remoteAddress.c_str(), nullptr, &hints, &result) != 0 || !result) {
            printf("[-] DNS resolution failed for %s\n", remoteAddress.c_str());
            char response[] = { 0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            send(context->clientSocket, response, sizeof(response), 0);
            SafeDelete(context);
            return;
        }

        remoteAddr.sin_addr = ((sockaddr_in*)result->ai_addr)->sin_addr;
        freeaddrinfo(result);
    }
    else {
        inet_pton(AF_INET, remoteAddress.c_str(), &remoteAddr.sin_addr);
    }

    DWORD bytesSent = 0;
    if (ConnectExPtr(context->remoteSocket, (sockaddr*)&remoteAddr, sizeof(remoteAddr),
        NULL, 0, &bytesSent, &context->remoteOverlapped) == FALSE) {
        int error = WSAGetLastError();
        if (error != ERROR_IO_PENDING) {
            printf("[-] ConnectEx failed: %d\n", error);
            char response[] = { 0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            send(context->clientSocket, response, sizeof(response), 0);
            SafeDelete(context);
            return;
        }
    }

    context->state = ProxyState::Connecting;
    context->remotePending = true;
}

void Socks5Proxy::HandleConnectionCompletion(ClientContext* context) {
    if (context->bytesTransferred != 0) {
        printf("[-] ConnectEx completion returned %d, connection failed\n", context->bytesTransferred);
        SafeDelete(context);
        return;
    }

    if (setsockopt(context->remoteSocket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == SOCKET_ERROR) {
        printf("[-] setsockopt SO_UPDATE_CONNECT_CONTEXT failed: %d\n", WSAGetLastError());
        SafeDelete(context);
        return;
    }

    printf("[+] Connection established to %s:%d\n",
        context->remoteHost.c_str(), context->remotePort);

    SendSuccessResponse(context);
    context->state = ProxyState::Established;

    StartReceive(context, true);
    StartReceive(context, false);
}

void Socks5Proxy::SendSuccessResponse(ClientContext* context) {
    char response[10] = { 0 };
    response[0] = 0x05;
    response[1] = 0x00;
    response[2] = 0x00;

    sockaddr_in remoteAddr;
    int addrLen = sizeof(remoteAddr);
    if (getsockname(context->remoteSocket, (sockaddr*)&remoteAddr, &addrLen) == 0) {
        response[3] = 0x01;
        memcpy(&response[4], &remoteAddr.sin_addr, 4);
        memcpy(&response[8], &remoteAddr.sin_port, 2);
        if (send(context->clientSocket, response, 10, 0) == SOCKET_ERROR) {
            printf("[-] Send response failed: %d\n", WSAGetLastError());
        }
    }
    else {
        printf("[-] getsockname failed, sending empty response\n");
        char emptyResponse[] = { 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        send(context->clientSocket, emptyResponse, sizeof(emptyResponse), 0);
    }
}

void Socks5Proxy::HandleDataTransfer(ClientContext* context, LPOVERLAPPED overlapped) {
    bool fromClient = (overlapped == &context->clientOverlapped);
    SOCKET fromSocket = fromClient ? context->clientSocket : context->remoteSocket;
    SOCKET toSocket = fromClient ? context->remoteSocket : context->clientSocket;

    if (fromSocket == INVALID_SOCKET || toSocket == INVALID_SOCKET) {
        SafeDelete(context);
        return;
    }

    if (context->bytesTransferred == 0) {
        printf("[-] Connection closed by %s\n", fromClient ? "client" : "remote");
        SafeDelete(context);
        return;
    }

    char* buffer = fromClient ? context->clientBuffer : context->remoteBuffer;
    DWORD bytesToSend = context->bytesTransferred;
    WSABUF wsaBuf;
    wsaBuf.buf = buffer;
    wsaBuf.len = bytesToSend;

    printf("[DEBUG] WSASend queued %d bytes from %s to %s\n",
        bytesToSend,
        fromClient ? "client" : "remote",
        fromClient ? "remote" : "client");

    if (bytesToSend > 5 && strncmp(buffer, "HTTP/", 5) == 0)
        printf("[DEBUG] HTTP response: %.100s\n", buffer);
    else if (bytesToSend > 3 && strncmp(buffer, "GET", 3) == 0)
        printf("[DEBUG] HTTP request: %.100s\n", buffer);

    DWORD bytesSent = 0;
    DWORD flags = 0;
    OVERLAPPED* sendOverlapped = fromClient ? &context->remoteOverlapped : &context->clientOverlapped;

    memset(sendOverlapped, 0, sizeof(OVERLAPPED));
    int result = WSASend(toSocket, &wsaBuf, 1, &bytesSent, flags, sendOverlapped, NULL);
    if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != ERROR_IO_PENDING) {
            printf("[-] WSASend failed: %d\n", err);
            SafeDelete(context);
            return;
        }
    }

    if (fromClient)
        context->remotePending = true;
    else
        context->clientPending = true;
}

void Socks5Proxy::StartReceive(ClientContext* context, bool fromClient) {
    SOCKET socket = fromClient ? context->clientSocket : context->remoteSocket;
    if (socket == INVALID_SOCKET) return;

    if ((fromClient && context->clientPending) || (!fromClient && context->remotePending)) {
        return;
    }

    WSABUF* wsaBuf = fromClient ? &context->clientWsaBuf : &context->remoteWsaBuf;
    wsaBuf->len = BUFFER_SIZE;
    wsaBuf->buf = fromClient ? context->clientBuffer : context->remoteBuffer;

    OVERLAPPED* overlapped = fromClient ? &context->clientOverlapped : &context->remoteOverlapped;
    memset(overlapped, 0, sizeof(OVERLAPPED));

    DWORD flags = 0;
    DWORD bytesReceived = 0;

    printf("[DEBUG] Starting WSARecv on %s\n", fromClient ? "client" : "remote");

    int result = WSARecv(socket, wsaBuf, 1, &bytesReceived, &flags, overlapped, NULL);
    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != ERROR_IO_PENDING) {
            printf("[-] WSARecv failed: %d\n", error);
            SafeDelete(context);
            return;
        }
    }

    if (fromClient) {
        context->clientPending = true;
    }
    else {
        context->remotePending = true;
    }
}

void Socks5Proxy::Run() {
    for (int i = 0; i < MAX_PENDING_ACCEPTS; i++) {
        StartAccept();
    }

    DWORD bytesTransferred;
    ULONG_PTR completionKey;
    LPOVERLAPPED overlapped;

    while (true) {
        BOOL success = GetQueuedCompletionStatus(
            iocpHandle, &bytesTransferred, &completionKey, &overlapped, INFINITE);

        ClientContext* context = nullptr;
        if (overlapped) {
            if (completionKey == (ULONG_PTR)this) {
                context = CONTAINING_RECORD(overlapped, ClientContext, clientOverlapped);
                if (context) {
                    ProcessNewConnection(context);
                    StartAccept();
                }
                continue;
            }

            context = (ClientContext*)completionKey;
            if (!context || context->proxy != this) {
                printf("[-] Invalid context detected\n");
                if (context) SafeDelete(context);
                StartAccept();
                continue;
            }

            if (context->clientSocket == INVALID_SOCKET ||
                (context->remoteSocket == INVALID_SOCKET && context->state == ProxyState::Established)) {
                SafeDelete(context);
                StartAccept();
                continue;
            }
        }

        if (!success) {
            DWORD error = GetLastError();
            if (context) {
                printf("[-] Operation failed for %s: %d\n", context->clientIP, error);
                SafeDelete(context);
            }
            StartAccept();
            continue;
        }

        if (!context) {
            StartAccept();
            continue;
        }

        context->bytesTransferred = bytesTransferred;
        context->lastActivityTime = GetTickCount64();
        ProcessClientOperation(context, overlapped);
    }
}