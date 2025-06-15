#ifndef EVASION_H
#define EVASION_H

#include <windows.h>

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

extern PPEB _getPeb(void);
extern BYTE _checkDebugger(void);

void isDebuggerModeOn();

#endif
