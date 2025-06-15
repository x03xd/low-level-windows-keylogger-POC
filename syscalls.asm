section .data
    extern g_NtCreateThreadExSSN
    extern g_NtCreateThreadExSyscall
    extern g_NtCloseSSN
    extern g_NtCloseSyscall

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
