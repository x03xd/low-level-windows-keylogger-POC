#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "sender/sender.h"
#include "utils/mutex/mutex-handler.h"


void initSocketClient(void* param) {
    HANDLE hMutex = (HANDLE)param;
    WSADATA wsaData;

    int socketResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (socketResult != 0) {
        exit(0);
    }

    SOCKET WSAAPI clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        exit(0);
    }

    struct sockaddr_in clientAddress;
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(4321); 
    clientAddress.sin_addr.s_addr = inet_addr("127.0.0.9");

    socketResult = connect(clientSocket, (struct sockaddr*)&clientAddress, sizeof(clientAddress));
    if (socketResult == SOCKET_ERROR) {
        exit(0);
    }

    send_(clientSocket, socketResult, hMutex);
}

void send_(SOCKET clientSocket, int socketResult, HANDLE hMutex) {
    int retries = 0;
    int max_retries = 20;
    int success = 0;
    time_t wait_time = 5;
    time_t max_wait_time = 16;

    while (retries < max_retries) {
        if (result != NULL && strlen(result) > 0) {

            lockMutex(hMutex);
            char buffer[strlen(result) + strlen(userId) + 64];
            snprintf(buffer, sizeof(buffer), "%s|~|%s", result, userId);
            unlockMutex(hMutex);

            socketResult = send(clientSocket, buffer, (int)strlen(buffer), 0);
            if (socketResult == SOCKET_ERROR) {
                retries++;
                if (retries >= max_retries) {
                    break;
                }
                wait_time = (wait_time * 2 > max_wait_time) ? max_wait_time : wait_time * 2;
            }

            lockMutex(hMutex);
            result[0] = '\0';
            unlockMutex(hMutex);

        }
        Sleep(wait_time);
    }

    closesocket(clientSocket);
    WSACleanup();
    return;
}
