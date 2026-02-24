/**
 * Multi-Client TCP Test Server for Packet Capture Testing
 * 
 * TCP server that accepts multiple clients simultaneously using threads.
 * Each client connection is handled in a separate thread.
 * Useful for testing TCP packet resend functionality.
 * 
 * Usage: tcp_server_multi.exe [port]
 * Default port: 12345
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT "12345"
#define BUFFER_SIZE 4096

volatile LONG g_ClientCount = 0;
volatile LONG g_TotalConnections = 0;

void print_hex(const char* data, int len) {
    printf("Hex: ");
    for (int i = 0; i < len && i < 64; i++) {
        printf("%02X ", (unsigned char)data[i]);
    }
    if (len > 64) printf("...");
    printf("\n");
}

struct ClientInfo {
    SOCKET socket;
    struct sockaddr_in addr;
    int clientId;
};

DWORD WINAPI ClientHandler(LPVOID param) {
    ClientInfo* info = (ClientInfo*)param;
    SOCKET clientSocket = info->socket;
    int clientId = info->clientId;
    char clientIP[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &info->addr.sin_addr, clientIP, INET_ADDRSTRLEN);
    int clientPort = ntohs(info->addr.sin_port);
    
    printf("[Client %d] Connected from %s:%d\n", clientId, clientIP, clientPort);
    
    char recvBuffer[BUFFER_SIZE];
    int msgCount = 0;
    
    while (1) {
        int recvResult = recv(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0);
        
        if (recvResult > 0) {
            recvBuffer[recvResult] = '\0';
            msgCount++;
            
            printf("\n[Client %d][Msg %d] Received %d bytes:\n", clientId, msgCount, recvResult);
            printf("Text: %s\n", recvBuffer);
            print_hex(recvBuffer, recvResult);
            
            // Echo back with prefix
            char response[BUFFER_SIZE + 128];
            snprintf(response, sizeof(response), "[Server -> Client %d][Echo #%d] %s", 
                     clientId, msgCount, recvBuffer);
            int sendResult = send(clientSocket, response, (int)strlen(response), 0);
            
            if (sendResult == SOCKET_ERROR) {
                printf("[Client %d] Send failed: %d\n", clientId, WSAGetLastError());
                break;
            }
            printf("[Client %d] Sent echo response (%d bytes)\n", clientId, sendResult);
            
        } else if (recvResult == 0) {
            printf("\n[Client %d] Disconnected gracefully\n", clientId);
            break;
        } else {
            int err = WSAGetLastError();
            if (err == WSAECONNRESET) {
                printf("\n[Client %d] Connection reset by peer\n", clientId);
            } else {
                printf("\n[Client %d] Recv failed: %d\n", clientId, err);
            }
            break;
        }
    }
    
    closesocket(clientSocket);
    InterlockedDecrement(&g_ClientCount);
    printf("[Client %d] Handler exiting. Active clients: %ld\n", clientId, g_ClientCount);
    
    delete info;
    return 0;
}

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    
    const char* port = (argc > 1) ? argv[1] : DEFAULT_PORT;
    
    printf("=== Multi-Client TCP Test Server ===\n");
    printf("For testing packet capture and TCP resend\n");
    printf("Accepts multiple simultaneous connections\n\n");
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    
    // Resolve address
    if (getaddrinfo(NULL, port, &hints, &result) != 0) {
        printf("getaddrinfo failed\n");
        WSACleanup();
        return 1;
    }
    
    // Create socket
    listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (listenSocket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    
    // Allow address reuse
    int opt = 1;
    setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    // Bind
    if (bind(listenSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    freeaddrinfo(result);
    
    // Listen
    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        printf("listen failed: %d\n", WSAGetLastError());
        closesocket(listenSocket);
        WSACleanup();
        return 1;
    }
    
    printf("[*] Server listening on port %s\n", port);
    printf("[*] PID: %lu (use this for packet capture)\n", GetCurrentProcessId());
    printf("[*] Waiting for connections (Ctrl+C to stop)...\n\n");
    
    while (1) {
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket == INVALID_SOCKET) {
            printf("accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        // Create client info
        ClientInfo* info = new ClientInfo;
        info->socket = clientSocket;
        info->addr = clientAddr;
        info->clientId = InterlockedIncrement(&g_TotalConnections);
        
        InterlockedIncrement(&g_ClientCount);
        printf("\n[*] New connection! Active clients: %ld, Total connections: %ld\n", 
               g_ClientCount, g_TotalConnections);
        
        // Create thread to handle client
        HANDLE thread = CreateThread(NULL, 0, ClientHandler, info, 0, NULL);
        if (thread == NULL) {
            printf("CreateThread failed: %d\n", GetLastError());
            closesocket(clientSocket);
            delete info;
            InterlockedDecrement(&g_ClientCount);
        } else {
            CloseHandle(thread); // Let thread run independently
        }
    }
    
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
