sub rsp, rsi
xor rcx, rcx
xor al, al
Copy_input:
cmp rsi, rcx
je  Slice_code
inc rdi
inc rsp
mov al, byte ptr [rdi-1]
mov byte ptr [rsp-1], al
inc rcx
jmp Copy_input
Slice_code:
mov	 qword ptr[rsp-16], 0x400
movzx	 r14d, byte ptr[rsp-6]
mov	 dword ptr[rsp-20], r14d
movsxd	 rax, dword ptr[rsp-20]
mov	 qword ptr[rsp-28], rax
mov	 ebx, dword ptr[rsp-28]
lea	 ecx, [rbx-48]
mov	 dword ptr[rsp-32], ecx
mov	 ecx, dword ptr[rsp-32]
mov	 ecx, ecx
mov	 dword ptr[rsp-36], ecx
mov	 qword ptr[rsp-44], 0x0
mov	 ecx, dword ptr[rsp-36]
mov	 rsi, qword ptr[rsp-44]
add	 rsi, rcx
mov	 qword ptr[rsp-52], rsi
mov	 qword ptr[rsp-60], 0x246
mov	 rsi, qword ptr[rsp-52]
mov	 ah, byte ptr[rsp-60]
sahf
cmove	 rax, rsi
mov	 qword ptr[rsp-68], rax
mov	 al, byte ptr[rsp-68]
cqo
mov	 byte ptr[rsp-68], dl
mov	 rcx, qword ptr[rsp-16]
idiv	 rcx
mov	 qword ptr[rsp-76], rax
mov	 rdi, qword ptr[rsp-76]
mov	 rdx, rdi
mov	 qword ptr[rsp-84], rdx
mov	 rax, qword ptr[rsp-84]
ret