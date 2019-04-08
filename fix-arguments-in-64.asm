print:

__code64:
; save 32 bit registers
mov r14d, edi
mov r15d, esi
; save return pointer
mov r13d, [rsp]
add rsp, 4
; TODO save edi and esi register

; Fix registers:
; If paramteers are 64 bit, just pop them
pop rdi
pop rsi
pop rdx
pop rcx
pop r9
pop r8

; For pointer (which is 32 bit) or unsigned long or 32 bit value
mov edi, [rsp]
add rsp, 4
mov esi, [rsp]
add rsp, 4
mov edx, [rsp]
add rsp, 4
mov ecx, [rsp]
add rsp, 4
mov r9d, [rsp]
add rsp, 4
mov r8d, [rsp]
; or 32 bit signed long passed
movsx rdi, DWORD [rsp]
add rsp, 4
movsx rsi, DWORD  [rsp]
add rsp, 4
movsx rdx, DWORD [rsp]
add rsp, 4
movsx rcx, DWORD [rsp]
add rsp, 4
movsx r9, DWORD [rsp]
add rsp, 4
movsx r8, DWORD [rsp]



; next args are already on the stack?

; Fix alignment
mov r12, rsp
and rsp, -16

call print
; Fix back alignment
mov rsp, r12

; restore return pointer
sub rsp, 4
mov [rsp], r13d

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

; Fix edi and esi
mov edi, r14d
mov esi, r15d

; switch to 32 bits
sub rsp, 8
mov dword [rsp+4], 0x23
mov dword [rsp], exit
retf

exit:
        or      edi, -1
        call    exit


