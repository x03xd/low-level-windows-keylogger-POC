#ifndef SHARED_H
#define SHARED_H

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

#endif
