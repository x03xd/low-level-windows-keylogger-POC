section .data
    extern g_NtOpenProcessSSN
    extern g_NtOpenProcessSyscall
    extern g_NtAllocateVirtualMemoryExSSN
    extern g_NtAllocateVirtualMemoryExSyscall
    extern g_NtWriteVirtualMemorySSN
    extern g_NtWriteVirtualMemorySyscall
    extern g_NtProtectVirtualMemorySSN
    extern g_NtProtectVirtualMemorySyscall
    extern g_NtCreateThreadExSSN
    extern g_NtCreateThreadExSyscall
    extern g_NtFreeVirtualMemorySSN
    extern g_NtFreeVirtualMemorySyscall
    extern g_NtCloseSSN
    extern g_NtCloseSyscall
    extern g_NtWaitForSingleObjectSSN
    extern g_NtWaitForSingleObjectSyscall

section .text
    global NtOpenProcess
    NtOpenProcess:
        mov r10, rcx
        mov eax, [g_NtOpenProcessSSN]
        jmp qword [g_NtOpenProcessSyscall]
        ret

    global NtAllocateVirtualMemoryEx
    NtAllocateVirtualMemoryEx:
        mov r10, rcx
        mov eax, [g_NtAllocateVirtualMemoryExSSN]
        jmp qword [g_NtAllocateVirtualMemoryExSyscall]
        ret

    global NtWriteVirtualMemory
    NtWriteVirtualMemory:
        mov r10, rcx
        mov eax, [g_NtWriteVirtualMemorySSN]
        jmp qword [g_NtWriteVirtualMemorySyscall]
        ret

    global NtProtectVirtualMemory
    NtProtectVirtualMemory:
        mov r10, rcx
        mov eax, [g_NtProtectVirtualMemorySSN]
        jmp qword [g_NtProtectVirtualMemorySyscall]
        ret

    global NtCreateThreadEx
    NtCreateThreadEx:
        mov r10, rcx
        mov eax, [g_NtCreateThreadExSSN]
        jmp qword [g_NtCreateThreadExSyscall]
        ret

    global NtFreeVirtualMemory
    NtFreeVirtualMemory:
        mov r10, rcx
        mov eax, [g_NtFreeVirtualMemorySSN]
        jmp qword [g_NtFreeVirtualMemorySyscall]
        ret

    global NtClose
    NtClose:
        mov r10, rcx
        mov eax, [g_NtCloseSSN]
        jmp qword [g_NtCloseSyscall]
        ret

    global NtWaitForSingleObject
    NtWaitForSingleObject:
        mov r10, rcx
        mov eax, [g_NtWaitForSingleObjectSSN]
        jmp qword [g_NtWaitForSingleObjectSyscall]
        ret

    global _getPeb

_getPeb:
    mov rax, gs:[0x60] 
    ret
