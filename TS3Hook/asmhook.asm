; Initialized data
.data

.code

EXTERN printf: PROC
EXTERN print_in_format: QWORD
EXTERN packet_in_hook_return: QWORD

PUBLIC packet_in_hook1

pushaq macro
	push rax
	push rbx
	push rcx
	push rdx
	push rbp
	push rsi
	push rdi
	push r8
	push r9
	push r10
	push r11
	push r12
	push r13
	push r14
	push r15
endm

popaq macro
	pop r15
	pop r14
	pop r13
	pop r12
	pop r11
	pop r10
	pop r9
	pop r8
	pop rdi
	pop rsi
	pop rbp
	pop rdx
	pop rcx
	pop rbx
	pop rax
endm

packet_in_hook1 proc
	mov     rcx, [r14+80]
	mov     rax, [rcx]
	mov     byte ptr [rsp+32], 0
	mov     r9, [r14+88]
	mov     r8, r14
	mov     rdx, rbx

	pushaq

	MOV r8, QWORD PTR [rdx+8]
	ADD r8, 11 ; str
	MOV edx, DWORD PTR [rdx+16]
	SUB edx, 11 ; len
	MOV rcx, print_in_format
	call printf

	popaq

	jmp packet_in_hook_return
packet_in_hook1 endp

END