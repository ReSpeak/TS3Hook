; Initialized data
.data

.code

EXTERN log_in_packet: PROC
EXTERN log_out_packet: PROC
EXTERN packet_in_hook_return: QWORD
EXTERN packet_out_hook_return: QWORD

PUBLIC packet_in_hook1

pushaq macro
	PUSH    rax
	PUSH    rbx
	PUSH    rcx
	PUSH    rdx
	PUSH    rbp
	PUSH    rsi
	PUSH    rdi
	PUSH    r8
	PUSH    r9
	PUSH    r10
	PUSH    r11
	PUSH    r12
	PUSH    r13
	PUSH    r14
	PUSH    r15
endm

popaq macro
	POP     r15
	POP     r14
	POP     r13
	POP     r12
	POP     r11
	POP     r10
	POP     r9
	POP     r8
	POP     rdi
	POP     rsi
	POP     rbp
	POP     rdx
	POP     rcx
	POP     rbx
	POP     rax
endm

packet_in_hook1 proc
	; Restore origial
	MOV     rcx, [r14+80]
	MOV     rax, [rcx]
	MOV     byte ptr [rsp+32], 0
	MOV     r9, [r14+88]
	MOV     r8, r14
	MOV     rdx, rbx

	pushaq
	SUB rsp, 32

	; Log in-packet
	MOV     rcx, QWORD PTR [rdx+8]
	ADD     rcx, 11 ; str
	MOV     edx, DWORD PTR [rdx+16]
	SUB     edx, 11 ; len
	CALL    log_in_packet

	ADD rsp, 32
	popaq

	JMP     packet_in_hook_return
packet_in_hook1 endp

packet_out_hook1 proc
	pushaq
	SUB rsp, 32

	; Log out-packet
	MOV     rcx, QWORD PTR [rdi]
	ADD     rcx, 13 ; str
	MOV     edx, DWORD PTR [rdi+8]
	SUB     edx, 13 ; len
	CALL    log_out_packet

	ADD rsp, 32
	popaq

	; Restore origial
	MOV     [rbp+0], eax
	CMP     eax, 1
	SETZ    cl
	MOV     [rsp+68], cl
	CMP     BYTE PTR [rsp+64], 0

	JMP     packet_out_hook_return
packet_out_hook1 endp

packet_out_hook2 proc
	pushaq
	SUB     rsp, 32

	; Log out-packet
	MOV     rcx, QWORD PTR [rdi]
	ADD     rcx, 13 ; str
	MOV     edx, DWORD PTR [rdi+8]
	SUB     edx, 13 ; len
	CALL    log_out_packet

	ADD rsp, 32
	popaq

	; Restore origial
	MOV     [rbp-32], eax
	CMP     eax, 1
	SETZ    cl
	MOV     [rsp+80], cl
	CMP     BYTE PTR [rsp+64], 0

	JMP     packet_out_hook_return
packet_out_hook2 endp

packet_out_hook3 proc
	; Restore origial
	MOV     rdx, [rax]
	MOV     [rsp+80], rdx
	MOV     [rsp+120], rdx
	MOV     rbx, [rax+8]

	pushaq

	LEA     eax, [rdi-2]
	CMP     al, 1
	JA      _skip_packet
	TEST    r9b, r9b
	JNZ     _skip_packet

	SUB     rsp, 32

	; Log out-packet
	MOV     rcx, QWORD PTR [rsi]
	ADD     rcx, 13 ; str
	MOV     edx, DWORD PTR [rsi+8]
	SUB     edx, 13 ; len
	CALL    log_out_packet

	ADD     rsp, 32

	_skip_packet:
	popaq

	JMP     packet_out_hook_return
packet_out_hook3 endp

END