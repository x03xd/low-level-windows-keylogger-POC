#include "utils/mutex/mutex-handler.h"


void lockMutex(HANDLE hMutex) {
    if (NtWaitForSingleObject(hMutex, FALSE, NULL) != STATUS_SUCCESS) {
        exit(0);
    }
}

void unlockMutex(HANDLE hMutex) {
    if (NtReleaseMutant(hMutex, NULL) != STATUS_SUCCESS) {
        exit(0);
    }
}
