section .data
    extern g_NtCreateThreadExSSN
    extern g_NtCreateThreadExSyscall
    extern g_NtCloseSSN
    extern g_NtCloseSyscall
    extern g_NtCloseSSN
    extern g_NtCloseSyscall
    extern g_NtCreateMutantSSN
    extern g_NtCreateMutantSyscall
    extern g_NtWaitForSingleObjectSSN
    extern g_NtWaitForSingleObjectSyscall
    extern g_NtReleaseMutantSSN
    extern g_NtReleaseMutantSyscall

section .text
    global NtCreateThreadEx
    NtCreateThreadEx:
        mov r10, rcx
        mov eax, [g_NtCreateThreadExSSN]
        jmp qword [g_NtCreateThreadExSyscall]
        ret

    global NtClose
    NtClose:
        mov r10, rcx
        mov eax, [g_NtCloseSSN]
        jmp qword [g_NtCloseSyscall]
        ret

    global NtCreateMutant
    NtCreateMutant:
        mov r10, rcx
        mov eax, [g_NtCreateMutantSSN]
        jmp qword [g_NtCreateMutantSyscall]
        ret

    global NtWaitForSingleObject
    NtWaitForSingleObject:
        mov r10, rcx
        mov eax, [g_NtWaitForSingleObjectSSN]
        jmp qword [g_NtWaitForSingleObjectSyscall]
        ret

    global NtReleaseMutant
    NtReleaseMutant:
        mov r10, rcx
        mov eax, [g_NtReleaseMutantSSN]
        jmp qword [g_NtReleaseMutantSyscall]
        ret

    global _getPeb
    global _checkDebugger

_getPeb:
    mov rax, gs:[0x60] 
    ret

_checkDebugger:
    xor eax, eax           
    call _getPeb       
    movzx eax, byte [rax+0x2] 
    ret
