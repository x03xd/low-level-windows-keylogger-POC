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
