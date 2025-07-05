#ifndef REGEDIT_H
#define REGEDIT_H

#include <windows.h>
#include "include/shared.h"

typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef NTSTATUS (NTAPI* fn_NtOpenKey)(
    _Out_ PHANDLE KeyHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS (NTAPI* fn_NtQueryValueKey)(
    _In_ HANDLE KeyHandle,
    _In_ PUNICODE_STRING ValueName,
    _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_writes_bytes_to_opt_(Length, *ResultLength) PVOID KeyValueInformation,
    _In_ ULONG Length,
    _Out_ PULONG ResultLength
);

typedef NTSTATUS (NTAPI* fn_NtClose)(
    IN HANDLE Handle
);

typedef NTSTATUS (NTAPI* fn_RtlCheckRegistryKey)(
    IN ULONG RelativeTo,
    IN PWSTR Path
);

typedef NTSTATUS (NTAPI RTL_QUERY_REGISTRY_ROUTINE)(
    _In_ PWSTR ValueName,
    _In_ ULONG ValueType,
    _In_ PVOID ValueData,
    _In_ ULONG ValueLength,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID EntryContext
);

typedef RTL_QUERY_REGISTRY_ROUTINE *PRTL_QUERY_REGISTRY_ROUTINE;

typedef struct _RTL_QUERY_REGISTRY_TABLE {
    PRTL_QUERY_REGISTRY_ROUTINE QueryRoutine;
    ULONG Flags;
    PWSTR Name;
    PVOID EntryContext;
    ULONG DefaultType;
    PVOID DefaultData;
    ULONG DefaultLength;
} RTL_QUERY_REGISTRY_TABLE, *PRTL_QUERY_REGISTRY_TABLE;

typedef NTSTATUS (NTAPI* fn_RtlQueryRegistryValues)(
    IN ULONG RelativeTo,
    IN PCWSTR Path,
    _Inout_ PRTL_QUERY_REGISTRY_TABLE QueryTable,
    _In_opt_ PVOID Context,
    _In_opt_ PVOID Environment
);

typedef NTSTATUS (NTAPI* fn_NtCreateKey)(
  OUT           PHANDLE            KeyHandle,
  IN            ACCESS_MASK        DesiredAccess,
  IN            POBJECT_ATTRIBUTES ObjectAttributes,
                  ULONG              TitleIndex,
  _In_opt_  PUNICODE_STRING    Class,
  IN            ULONG              CreateOptions,
  _Out_opt_ PULONG             Disposition
);

/**
 * @brief Opens a registry key and queries the user's UUID value.
 *
 * @param lpValueName Pointer to a constant, null-terminated wide-character string specifying the registry value name to query.
 * @return LPBYTE Pointer to a buffer containing binary data with the user's UUID.
 *
 */
LPBYTE queryRegedit(LPCWSTR lpValueName);

/**
 * @brief Creates or updates a registry record by setting a newly generated UUID under a specified key and value name.
 *
 * @param lpValueName Pointer to a constant, null-terminated wide-character string specifying the registry value name to set.
 * @param key Pointer to a constant, null-terminated wide-character string specifying the registry key path where the value will be set.
 * @param uuid Pointer to a null-terminated wide-character string containing the UUID to store.
 * @return DWORD Returns 0 on success, otherwise program exits.
 */
DWORD setRegeditKeyValue(LPCWSTR lpValueName, LPCWSTR key, LPCWSTR uuid);

/**
 * @brief Retrieves the user's UUID from the registry, or creates and returns a new UUID if none exists.
 *
 * @return Pointer to a buffer containing binary data with the user's UUID.
 */
LPBYTE getOrCreateAndGetUserId();

#endif
