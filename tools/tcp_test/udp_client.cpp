/**
 * UDP Test Client for Packet Capture Testing
 * 
 * Simple UDP client that sends messages to a server.
 * UDP is stateless, making it ideal for testing packet resend functionality.
 * 
 * Usage: udp_client.exe [host] [port]
 * Default: localhost:12346
 */

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "Ws2_32.lib")

#define DEFAULT_HOST "127.0.0.1"
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
    SOCKET clientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    char recvBuffer[BUFFER_SIZE];
    char sendBuffer[BUFFER_SIZE];
    int serverAddrLen = sizeof(serverAddr);
    
    const char* host = (argc > 1) ? argv[1] : DEFAULT_HOST;
    int port = (argc > 2) ? atoi(argv[2]) : DEFAULT_PORT;
    
    printf("=== UDP Test Client ===\n");
    printf("For testing packet capture and resend (UDP is stateless)\n\n");
    printf("[*] PID: %lu (use this for packet capture)\n\n", GetCurrentProcessId());
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    // Create UDP socket
    clientSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (clientSocket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Set receive timeout
    DWORD timeout = 2000; // 2 seconds
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
    
    // Setup server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons((u_short)port);
    inet_pton(AF_INET, host, &serverAddr.sin_addr);
    
    printf("[*] Target: %s:%d\n\n", host, port);
    printf("Commands:\n");
    printf("  Type a message and press Enter to send\n");
    printf("  'quit' or 'exit' to disconnect\n");
    printf("  'flood N' to send N test messages\n");
    printf("\n");
    printf("TIP: UDP is stateless - resent packets will be received as new messages!\n\n");
    
    int msgCount = 0;
    while (1) {
        printf("> ");
        fflush(stdout);
        
        if (fgets(sendBuffer, BUFFER_SIZE, stdin) == NULL) {
            break;
        }
        
        // Remove newline
        size_t len = strlen(sendBuffer);
        if (len > 0 && sendBuffer[len - 1] == '\n') {
            sendBuffer[len - 1] = '\0';
            len--;
        }
        
        if (len == 0) continue;
        
        // Check for commands
        if (strcmp(sendBuffer, "quit") == 0 || strcmp(sendBuffer, "exit") == 0) {
            printf("[*] Exiting...\n");
            break;
        }
        
        // Flood command
        if (strncmp(sendBuffer, "flood ", 6) == 0) {
            int count = atoi(sendBuffer + 6);
            if (count <= 0) count = 10;
            printf("[*] Sending %d flood messages...\n", count);
            
            for (int i = 1; i <= count; i++) {
                char floodMsg[256];
                snprintf(floodMsg, sizeof(floodMsg), "FLOOD_MSG_%04d_TIME_%lu", i, GetTickCount());
                
                int sendResult = sendto(clientSocket, floodMsg, (int)strlen(floodMsg), 0,
                                        (struct sockaddr*)&serverAddr, sizeof(serverAddr));
                if (sendResult == SOCKET_ERROR) {
                    printf("sendto failed: %d\n", WSAGetLastError());
                    break;
                }
                
                // Try to receive response (non-blocking with timeout)
                serverAddrLen = sizeof(serverAddr);
                int recvResult = recvfrom(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0,
                                          (struct sockaddr*)&serverAddr, &serverAddrLen);
                if (recvResult > 0) {
                    recvBuffer[recvResult] = '\0';
                }
                
                if (i % 10 == 0 || i == count) {
                    printf("  Sent %d/%d messages\n", i, count);
                }
                
                Sleep(50);
            }
            printf("[+] Flood complete\n");
            continue;
        }
        
        // Regular message
        msgCount++;
        int sendResult = sendto(clientSocket, sendBuffer, (int)len, 0,
                                (struct sockaddr*)&serverAddr, sizeof(serverAddr));
        if (sendResult == SOCKET_ERROR) {
            printf("sendto failed: %d\n", WSAGetLastError());
            continue;
        }
        
        printf("[>] Sent %d bytes\n", sendResult);
        print_hex(sendBuffer, sendResult);
        
        // Receive response
        serverAddrLen = sizeof(serverAddr);
        int recvResult = recvfrom(clientSocket, recvBuffer, BUFFER_SIZE - 1, 0,
                                  (struct sockaddr*)&serverAddr, &serverAddrLen);
        if (recvResult > 0) {
            recvBuffer[recvResult] = '\0';
            printf("[<] Received %d bytes:\n", recvResult);
            printf("Text: %s\n", recvBuffer);
            print_hex(recvBuffer, recvResult);
        } else if (recvResult == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                printf("[!] No response (timeout)\n");
            } else {
                printf("recvfrom failed: %d\n", err);
            }
        }
        
        printf("\n");
    }
    
    closesocket(clientSocket);
    WSACleanup();
    printf("[*] Done\n");
    return 0;
}
