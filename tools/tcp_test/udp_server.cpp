/**
 * UDP Test Server for Packet Capture Testing
 * 
 * Simple UDP server that listens on a port and echoes received data.
 * UDP is stateless, making it ideal for testing packet resend functionality.
 * 
 * Usage: udp_server.exe [port]
 * Default port: 12346
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_PORT 12346
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
    SOCKET serverSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr, clientAddr;
    char recvBuffer[BUFFER_SIZE];
    int clientAddrLen = sizeof(clientAddr);
    int recvResult;
    
    int port = (argc > 1) ? atoi(argv[1]) : DEFAULT_PORT;
    
    printf("=== UDP Test Server ===\n");
    printf("For testing packet capture and resend (UDP is stateless)\n\n");
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    // Create UDP socket
    serverSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (serverSocket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Allow address reuse
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    // Bind
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons((u_short)port);
    
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        printf("bind failed: %d\n", WSAGetLastError());
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }
    
    printf("[*] UDP Server listening on port %d\n", port);
    printf("[*] PID: %lu (use this for packet capture)\n", GetCurrentProcessId());
    printf("[*] Waiting for datagrams...\n\n");
    printf("TIP: UDP is stateless - resent packets will be received as new messages!\n\n");
    
    int msgCount = 0;
    while (1) {
        // Receive datagram
        clientAddrLen = sizeof(clientAddr);
        recvResult = recvfrom(serverSocket, recvBuffer, BUFFER_SIZE - 1, 0,
                              (struct sockaddr*)&clientAddr, &clientAddrLen);
        
        if (recvResult > 0) {
            recvBuffer[recvResult] = '\0';
            msgCount++;
            
            char clientIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);
            
            printf("\n[%d] Received %d bytes from %s:%d\n", 
                   msgCount, recvResult, clientIP, ntohs(clientAddr.sin_port));
            printf("Text: %s\n", recvBuffer);
            print_hex(recvBuffer, recvResult);
            
            // Echo back with prefix
            char response[BUFFER_SIZE + 64];
            snprintf(response, sizeof(response), "[ECHO #%d] %s", msgCount, recvBuffer);
            
            int sendResult = sendto(serverSocket, response, (int)strlen(response), 0,
                                    (struct sockaddr*)&clientAddr, clientAddrLen);
            
            if (sendResult == SOCKET_ERROR) {
                printf("sendto failed: %d\n", WSAGetLastError());
            } else {
                printf("[>] Sent echo response (%d bytes)\n", sendResult);
            }
        } else if (recvResult == SOCKET_ERROR) {
            printf("recvfrom failed: %d\n", WSAGetLastError());
        }
    }
    
    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
