void send_(SOCKET clientSocket, int socketResult, HANDLE hMutex) {
    int retries = 0;
    int max_retries = 20;
    int success = 0;
    time_t wait_time = 5;
    time_t max_wait_time = 16;

    while (retries < max_retries) {
        if (result != NULL && strlen(result) > 0) {
            lockMutex(hMutex);
            DWORD size;
            char* buffer = prepareRequest(result, userId, &size);
            if (!buffer) break;
            unlockMutex(hMutex);

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

        }
        Sleep(wait_time);
    }

    NtClose(hMutex);
    closesocket(clientSocket);
    WSACleanup();
    exit(0);
}