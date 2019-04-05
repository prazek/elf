print:

__code64:
; Fix registers
; void print(char *str);
; got parameters on stack (top is first arg)
pop rdi
pop rsi
pop rdx
pop rcx
pop r9
pop r8
; next args are already on the stack?

; fix alignment?
call print
; result in eax/rax
; try to convert to 32 bits


__check_signed_long_long:
        mov     edx, 2147483648
        mov     ecx, 4294967295
        add     rdx, rax
        cmp     rdx, rcx
        ja     ok
        jmp     exit
__check_unsigned_long_long:
        mov     ecx, 4294967295
        cmp     rax, rcx
        ja      exit
ok:

; switch to 32 bits
push 0x23
retf

exit:
        or      edi, -1
        call    exit


