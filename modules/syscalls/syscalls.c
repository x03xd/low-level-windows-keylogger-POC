#include <stdbool.h>
#include <stdio.h>
#include <tlhelp32.h>
#include "syscalls/syscalls.h"


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

VOID IndirectPrelude(HMODULE NtdllHandle, char NtFunctionName[], PDWORD NtFunctionSSN, PUINT_PTR NtFunctionSyscall) {
    DWORD SyscallNumber = 0;
    UINT_PTR NtFunctionAddress = 0;
    UCHAR SyscallOpcodes[2] = { 0x0F, 0x05 };
    
    NtFunctionAddress = getAddr(NtdllHandle, NtFunctionName);
    if (NtFunctionAddress == 0) {
        exit(0);
    }

    *NtFunctionSSN = ((PBYTE)(NtFunctionAddress + 0x4))[0];
    *NtFunctionSyscall = NtFunctionAddress + 0x12;

    if (memcmp(SyscallOpcodes, (PVOID)*NtFunctionSyscall, sizeof(SyscallOpcodes)) != 0) {
        exit(0);
    }
}

UINT_PTR getAddr(HMODULE module, char target[]) {
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)module;

    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)module + dosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY exportDirectoryEntry = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY* exportDirectory = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)module + exportDirectoryEntry.VirtualAddress);

    DWORD* nameRVAs = (DWORD*)((BYTE*)module + exportDirectory->AddressOfNames);
    WORD* nameOrdinals = (WORD*)((BYTE*)module + exportDirectory->AddressOfNameOrdinals);
    DWORD* functionRVAs = (DWORD*)((BYTE*)module + exportDirectory->AddressOfFunctions);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)module + nameRVAs[i]);
        if (strcmp(name, target) == 0) {
            WORD ordinal = nameOrdinals[i];
            DWORD functionRVA = functionRVAs[ordinal];
            return (UINT_PTR)module + functionRVA;
        }
    }
}

HMODULE getModuleHandle() {
    PPEB pPEB = _getPeb();
    PLIST_ENTRY hdr = &(pPEB->Ldr->InLoadOrderModuleList);
    PLIST_ENTRY ent = hdr->Flink;
    PLDR_DATA_TABLE_ENTRY entry = NULL;

    for (; hdr != ent; ent = ent->Flink){
        entry = (PLDR_DATA_TABLE_ENTRY)ent;
        if (wcscmp(entry->FullDllName.Buffer, L"C:\\Windows\\SYSTEM32\\ntdll.dll") == 0) {
            return (HMODULE)entry->DllBase;
        }
    }
    return NULL;
}
