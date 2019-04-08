        section .text
        global _start       ;Declaration for linker (ld)

_start:
		push 0x2b
		pop ds
		push 0x2b
		pop es
        jmp .call_print


.call_print:
; switch to 64 bits
push 0x33
push __code64
retf
__code64:


;  set segment registers
push 0x2b
pop ds
push 0x2b
pop es
ret

