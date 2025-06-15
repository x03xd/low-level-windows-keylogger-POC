section .text
    global _checkDebugger
    global _getPeb

_checkDebugger:
    xor eax, eax           
    call _getPeb       
    movzx eax, byte [rax+0x2] 
    ret

_getPeb:
    mov rax, gs:[0x60] 
    ret
