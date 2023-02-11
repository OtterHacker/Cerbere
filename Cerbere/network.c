#include "network.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

void sendBytes(char *server, char* port, PBYTE content, int contentSize, PBYTE *response, int *size) {
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL;
    struct addrinfo* ptr = NULL;
    struct addrinfo hints;
    int iResult;
   

    // Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("[x] Failed to start WSA Winsocks: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo(server, port, &hints, &result);
    if (iResult != 0) {
        printf("[x] Failed to get KDC IP info: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Attempt to connect to an address until one succeeds
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {

        // Create a SOCKET for connecting to server
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
            ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET) {
            printf("[x] Failed to connect to the KDC: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Connect to server.
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("[x] Failed to connect to server!\n");
        WSACleanup();
        return 1;
    }

    // Send an initial buffer
    int networkContentSize = htonl(contentSize);
    char test[4] = "";
    CopyMemory(test, &networkContentSize, sizeof(int));
    iResult = send(ConnectSocket, test, 4, 0);
    iResult = send(ConnectSocket, content, contentSize, 0);
    if (iResult == SOCKET_ERROR) {
        printf("[x] Failed to write data: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    char sizeBuff[4] = "";
    iResult = recv(ConnectSocket, sizeBuff, 4, 0);
    if (iResult < 0) {
        printf("[x] Failed to receive data size from KDC: %d\n", WSAGetLastError());
        exit(-1);
    }

    CopyMemory(size, sizeBuff, sizeof(int));
    *size = ntohl(*size) & 0x7fffffff;

    *response = calloc(*size, sizeof(char));
    if (!*response) {
        printf("[x] Failed to allocate KDC response buffer\n");
        exit(-1);
    }
    PBYTE buff = *response;
    int bufferSize = 0;
    do {
        iResult = recv(ConnectSocket, buff, *size, 0);
        if (iResult < 0) {
            printf("[x] Failed to receive data size from KDC: %d\n", WSAGetLastError());
            exit(-1);
        }
        buff += iResult;
        bufferSize += iResult;
    } while (bufferSize != *size);

    // cleanup
    closesocket(ConnectSocket);
    WSACleanup();

}