push    rbp
mov     rbp, rsp
mov     [rbp-18h], rdi
mov     eax, edx
mov     [rbp-28h], rcx
mov     [rbp-1Ch], si
mov     [rbp-20h], ax
movzx   eax, word ptr [rbp-20h]
mov     edx, 8
sub     edx, eax
mov     eax, edx
shl     eax, 3
mov     rdx, [rbp-18h]
mov     ecx, eax
shl     rdx, cl
mov     rax, rdx
mov     [rbp-10h], rax
movzx   eax, word ptr [rbp-20h]
mov     edx, 8
sub     edx, eax
mov     eax, edx
shl     eax, 3
mov     rdx, [rbp-10h]
mov     ecx, eax
shr     rdx, cl
mov     rax, rdx
mov     [rbp-8], rax
movzx   eax, word ptr [rbp-1Ch]
cmp     eax, 2
jz      loc_40061B
cmp     eax, 2
jg      loc_400601
cmp     eax, 1
jz      loc_40060D
jmp     loc_400644
loc_400601:cmp     eax, 4
jz      loc_40062A
cmp     eax, 8
jz      loc_400638
jmp     loc_400644
loc_40060D:mov     rax, [rbp-8]
mov     edx, eax
mov     rax, [rbp-28h]
mov     [rax], dl
jmp    loc_400644
loc_40061B:mov     rax, [rbp-8]
mov     edx, eax
mov     rax, [rbp-28h]
mov     [rax], dx
jmp    loc_400644
loc_40062A:mov     rax, [rbp-8]
mov     edx, eax
mov     rax, [rbp-28h]
mov     [rax], edx
jmp    loc_400644
loc_400638:mov     rdx, [rbp-8]
mov     rax, [rbp-28h]
mov     [rax], rdx
loc_400644:pop     rbp
ret
