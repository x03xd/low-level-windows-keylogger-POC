#ifndef MUTEX_HANDLER_H
#define MUTEX_HANDLER_H

#define STATUS_SUCCESS (NTSTATUS)0x00000000L

#include <windows.h>

extern NTSTATUS NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

extern NTSTATUS NtReleaseMutant(
    IN HANDLE MutantHandle,
    OUT PLONG PreviousCount OPTIONAL
);

/**
 * @brief Locks a mutex.
 *
 * @param hMutex Handle pointing to the mutex.
 *
 */
void lockMutex(HANDLE hMutex);

/**
 * @brief Unlocks a mutex.
 *
 * @param hMutex Handle pointing to the mutex.
 *
 */
void unlockMutex(HANDLE hMutex);

#endif
