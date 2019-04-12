print:

__code64:
; save 32 bit registers
mov r14d, edi
mov r15d, esi

; Fix alignment
mov r12, rsp
and rsp, -16
nop


; Fix registers:
; If paramteers are 64 bit, just pop them
mov rdi, [r12 + 4]
mov rsi, [r12 + 12]
mov rdx, [r12 + 20]
mov rcx, [r12 + 28]
mov r8, [r12 + 36]
mov r9, [r12 + 44]
nop

; For pointer (which is 32 bit) or unsigned long or 32 bit value
mov edi, [r12 + 4]
mov esi, [r12 + 8]
mov edx, [r12 + 12]
mov ecx, [r12 + 16]
mov r8d, [r12 + 20]
mov r9d, [r12 + 24]
nop

; or 32 bit signed long passed
movsx rdi, DWORD [r12 + 4]
movsx rsi, DWORD  [r12 + 8]
movsx rdx, DWORD [r12 + 12]
movsx rcx, DWORD [r12 + 16]
movsx r8, DWORD [r12 + 20]
movsx r9, DWORD [r12 + 24]


nop
; Put rest of the arguments:
mov rax, [r12 + 24]
movsx rax, DWORD [r12 + 24] ; for signed 32 bit types
mov eax, [r12 + 24]
push rax



mov rax, print
call rax
; Fix back rsp
mov rsp, r12

; restore return pointer

; Fix edi and esi
mov edi, r14d
mov esi, r15d

; result in eax/rax
; try to convert to 32 bits
__check_signed_long_long:
        mov     edx, 2147483648
        mov     ecx, 4294967295
        add     rdx, rax
        cmp     rdx, rcx
        jna     ok
        or      edi, -1
        call    exit

__check_unsigned_long_long:
        mov     ecx, 4294967295
        cmp     rax, rcx
        jna      ok
        or      edi, -1
        call    exit
__move_64_bit_to_eax_edx:
    mov rdx, rax
    shr rdx, 32
ok:
; switch to 32 bits
sub rsp, 8
mov dword [rsp+4], 0x23
mov dword [rsp], exit
retf

exit:


