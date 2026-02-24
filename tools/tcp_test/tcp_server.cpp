/**
 * TCP Test Server for Packet Capture Testing
 * 
 * Simple TCP server that listens on a port and echoes received data.
 * Useful for testing packet sniffing and resend functionality.
 * 
 * Usage: tcp_server.exe [port]
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

void print_hex(const char* data, int len) {
    printf("Hex: ");
    for (int i = 0; i < len && i < 64; i++) {
        printf("%02X ", (unsigned char)data[i]);
    }
    if (len > 64) printf("...");
    printf("\n");
}

int main(int argc, char* argv[]) {
    WSADATA wsaData;
    SOCKET listenSocket = INVALID_SOCKET;
    SOCKET clientSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    char recvBuffer[BUFFER_SIZE];
    int recvResult;
    
    const char* port = (argc > 1) ? argv[1] : DEFAULT_PORT;
    
    printf("=== TCP Test Server ===\n");
    printf("For testing packet capture and resend\n\n");
    
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
    printf("[*] Waiting for connections...\n\n");
    
    while (1) {
        // Accept connection
        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);
        clientSocket = accept(listenSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (clientSocket == INVALID_SOCKET) {
            printf("accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
        printf("[+] Client connected: %s:%d\n", clientIP, ntohs(clientAddr.sin_port));
        
        // Receive and echo loop
        int msgCount = 0;
        while (1) {
            recvResult = recv(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0);
            
            if (recvResult > 0) {
                recvBuffer[recvResult] = '\0';
                msgCount++;
                
                printf("\n[%d] Received %d bytes:\n", msgCount, recvResult);
                printf("Text: %s\n", recvBuffer);
                print_hex(recvBuffer, recvResult);
                
                // Echo back with prefix
                char response[BUFFER_SIZE + 64];
                snprintf(response, sizeof(response), "[ECHO #%d] %s", msgCount, recvBuffer);
                int sendResult = send(clientSocket, response, (int)strlen(response), 0);
                
                if (sendResult == SOCKET_ERROR) {
                    printf("send failed: %d\n", WSAGetLastError());
                    break;
                }
                printf("[>] Sent echo response (%d bytes)\n", sendResult);
                
            } else if (recvResult == 0) {
                printf("\n[-] Client disconnected\n");
                break;
            } else {
                printf("recv failed: %d\n", WSAGetLastError());
                break;
            }
        }
        
        closesocket(clientSocket);
        printf("[*] Waiting for next connection...\n\n");
    }
    
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}
