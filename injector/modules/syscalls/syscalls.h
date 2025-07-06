#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <stdbool.h>
#include <tlhelp32.h>
#include <windows.h>

typedef unsigned __int64 QWORD;
DWORD g_NtOpenProcessSSN;
QWORD g_NtOpenProcessSyscall;
DWORD g_NtAllocateVirtualMemoryExSSN;
QWORD g_NtAllocateVirtualMemoryExSyscall;
DWORD g_NtWriteVirtualMemorySSN;
QWORD g_NtWriteVirtualMemorySyscall;
DWORD g_NtProtectVirtualMemorySSN;
QWORD g_NtProtectVirtualMemorySyscall;
DWORD g_NtCreateThreadExSSN;
QWORD g_NtCreateThreadExSyscall;
DWORD g_NtFreeVirtualMemorySSN;
QWORD g_NtFreeVirtualMemorySyscall;
DWORD g_NtCloseSSN;
QWORD g_NtCloseSyscall;
DWORD g_NtWaitForSingleObjectSSN;
QWORD g_NtWaitForSingleObjectSyscall;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService; 
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    DWORD UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _MEM_EXTENDED_PARAMETER {
    union {
        struct {
            DWORD64 Type;
            DWORD64 Reserved;
        } DUMMYSTRUCTNAME;
        DWORD64 AsUlong64; 
    };
    union {
        DWORD64 ULong64;
        PVOID   Pointer;
        SIZE_T  Size;
        HANDLE  Handle;
        DWORD   ULong;
    } DUMMYUNIONNAME;
} MEM_EXTENDED_PARAMETER, *PMEM_EXTENDED_PARAMETER;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _PS_ATTRIBUTE
{
    ULONG_PTR Attribute;
    SIZE_T Size;
    union
    {
        ULONG_PTR Value;
        PVOID ValuePtr;
    };
    PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
    SIZE_T TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

extern NTSTATUS NtClose(
    _In_ HANDLE Handle
);

extern NTSTATUS NtFreeVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
);

extern NTSTATUS NtWriteVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(BufferSize) PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
);

extern NTSTATUS NtOpenProcess(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_ PCLIENT_ID ClientId
);

extern NTSTATUS NtAllocateVirtualMemoryEx(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection,
    _Inout_updates_opt_(ExtendedParameterCount) PMEM_EXTENDED_PARAMETER ExtendedParameters,
    _In_ ULONG ExtendedParameterCount
);

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

extern NTSTATUS NtProtectVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID *BaseAddress,
    IN OUT PULONG NumberOfBytesToProtect,
    IN ULONG NewAccessProtection,
    OUT PULONG OldAccessProtection
);

extern NTSTATUS NtWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
);

extern PPEB _getPeb(void);

/**
 * @brief Retrieves the syscall number and syscall instruction address for a given NT function.
 *
 * @param NtdllHandle Handle to the loaded ntdll.dll module.
 * @param NtFunctionName Pointer to a null-terminated string with the NT function name.
 * @param NtFunctionSSN Pointer to a DWORD that will receive the system call number (SSN).
 * @param NtFunctionSyscall Pointer to a UINT_PTR that will receive the address of the syscall instruction.
 * @return BOOL Returns TRUE if there is syscall instruction at the pointed memory address, otherwise FALSE.
 */
BOOL IndirectPrelude(HMODULE NtdllHandle, char NtFunctionName[], PDWORD NtFunctionSSN, PUINT_PTR NtFunctionSyscall);

/**
 * @brief Queries the process ID (PID) by process name.
 *
 * @param processName Pointer to a null-terminated string specifying the process name.
 *                    Must not be NULL.
 * @return DWORD Process ID if the process exists, otherwise returns 0.
 */
DWORD getProcessPID(const char* processName);

/**
 * @brief Retrieves the base address of ntdll.dll module by parsing the PEB.
 *
 * @return HMODULE Returns the base address of ntdll.dll if found, otherwise returns NULL.
 */
HMODULE getModuleHandle();

/**
 * @brief Retrieves the address of an exported function from a given module.
 *
 * @param module Handle to the module from which the function address will be retrieved.
 * @param target Null-terminated string representing the name of the function to locate.
 *
 * @return UINT_PTR Returns the address of the exported function if found, otherwise returns 0.
 */
UINT_PTR getAddr(HMODULE module, char target[]);

#endif
