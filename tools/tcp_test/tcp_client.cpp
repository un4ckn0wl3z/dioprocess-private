/**
 * TCP Test Client for Packet Capture Testing
 * 
 * Simple TCP client that connects to a server and sends messages.
 * Useful for testing packet sniffing and resend functionality.
 * 
 * Usage: tcp_client.exe [host] [port]
 * Default: localhost:12345
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
    SOCKET connectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL;
    struct addrinfo hints;
    char recvBuffer[BUFFER_SIZE];
    char sendBuffer[BUFFER_SIZE];
    int recvResult;
    
    const char* host = (argc > 1) ? argv[1] : DEFAULT_HOST;
    const char* port = (argc > 2) ? argv[2] : DEFAULT_PORT;
    
    printf("=== TCP Test Client ===\n");
    printf("For testing packet capture and resend\n\n");
    printf("[*] PID: %lu (use this for packet capture)\n\n", GetCurrentProcessId());
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    
    // Resolve address
    if (getaddrinfo(host, port, &hints, &result) != 0) {
        printf("getaddrinfo failed\n");
        WSACleanup();
        return 1;
    }
    
    // Create socket
    connectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (connectSocket == INVALID_SOCKET) {
        printf("socket failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }
    
    // Connect
    printf("[*] Connecting to %s:%s...\n", host, port);
    if (connect(connectSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR) {
        printf("connect failed: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(connectSocket);
        WSACleanup();
        return 1;
    }
    
    freeaddrinfo(result);
    printf("[+] Connected!\n\n");
    
    printf("Commands:\n");
    printf("  Type a message and press Enter to send\n");
    printf("  'quit' or 'exit' to disconnect\n");
    printf("  'flood N' to send N test messages\n");
    printf("  'binary' to send binary test data\n");
    printf("\n");
    
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
            printf("[*] Disconnecting...\n");
            break;
        }
        
        // Flood command
        if (strncmp(sendBuffer, "flood ", 6) == 0) {
            int count = atoi(sendBuffer + 6);
            if (count <= 0) count = 10;
            printf("[*] Sending %d flood messages...\n", count);
            
            for (int i = 1; i <= count; i++) {
                char floodMsg[256];
                snprintf(floodMsg, sizeof(floodMsg), "FLOOD_MSG_%04d_TIMESTAMP_%lu", i, GetTickCount());
                
                int sendResult = send(connectSocket, floodMsg, (int)strlen(floodMsg), 0);
                if (sendResult == SOCKET_ERROR) {
                    printf("send failed: %d\n", WSAGetLastError());
                    break;
                }
                
                // Brief delay to avoid overwhelming
                Sleep(50);
                
                // Receive response
                recvResult = recv(connectSocket, recvBuffer, BUFFER_SIZE - 1, 0);
                if (recvResult > 0) {
                    recvBuffer[recvResult] = '\0';
                }
                
                if (i % 10 == 0 || i == count) {
                    printf("  Sent %d/%d messages\n", i, count);
                }
            }
            printf("[+] Flood complete\n");
            continue;
        }
        
        // Binary command
        if (strcmp(sendBuffer, "binary") == 0) {
            printf("[*] Sending binary test data...\n");
            char binaryData[256];
            for (int i = 0; i < 256; i++) {
                binaryData[i] = (char)i;
            }
            
            int sendResult = send(connectSocket, binaryData, 256, 0);
            if (sendResult == SOCKET_ERROR) {
                printf("send failed: %d\n", WSAGetLastError());
                continue;
            }
            printf("[>] Sent %d bytes of binary data\n", sendResult);
            print_hex(binaryData, 256);
            
            // Receive response
            recvResult = recv(connectSocket, recvBuffer, BUFFER_SIZE - 1, 0);
            if (recvResult > 0) {
                recvBuffer[recvResult] = '\0';
                printf("[<] Received %d bytes\n", recvResult);
                print_hex(recvBuffer, recvResult);
            }
            continue;
        }
        
        // Regular message
        msgCount++;
        int sendResult = send(connectSocket, sendBuffer, (int)len, 0);
        if (sendResult == SOCKET_ERROR) {
            printf("send failed: %d\n", WSAGetLastError());
            break;
        }
        
        printf("[>] Sent %d bytes\n", sendResult);
        print_hex(sendBuffer, sendResult);
        
        // Receive response
        recvResult = recv(connectSocket, recvBuffer, BUFFER_SIZE - 1, 0);
        if (recvResult > 0) {
            recvBuffer[recvResult] = '\0';
            printf("[<] Received %d bytes:\n", recvResult);
            printf("Text: %s\n", recvBuffer);
            print_hex(recvBuffer, recvResult);
        } else if (recvResult == 0) {
            printf("[-] Server disconnected\n");
            break;
        } else {
            printf("recv failed: %d\n", WSAGetLastError());
            break;
        }
        
        printf("\n");
    }
    
    closesocket(connectSocket);
    WSACleanup();
    printf("[*] Disconnected\n");
    return 0;
}
