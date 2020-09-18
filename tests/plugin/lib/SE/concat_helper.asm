                push    rbp
                mov     rbp, rsp
                mov     [rbp-18h], rdi
                mov     [rbp-28h], rdx
                mov     eax, ecx
                mov     edx, r8d
                mov     [rbp-38h], r9
                mov     [rbp-1ch], si
                mov     [rbp-20h], ax
                mov     [rbp-2ch], dx
                movzx   eax, [rbp-1ch]
                shl     eax, 3
                mov     rdx, [rbp-28h]
                mov     ecx, eax
                shl     rdx, cl
                mov     rax, rdx
                mov     [rbp-10h], rax
                mov     rax, [rbp-18h]
                or      rax, [rbp-10h]
                mov     [rbp-8], rax
                movzx   eax, [rbp-2ch]
                cmp     eax, 2
                jz      short loc_size_2
                cmp     eax, 2
                jg      short loc_size_cmp
                cmp     eax, 1
                jz      short loc_size_1
                jmp     short loc_4006E3

loc_size_cmp:
                cmp     eax, 4
                jz      short loc_size_4
                cmp     eax, 8
                jz      short loc_size_8
                jmp     short loc_4006E3

loc_size_1:
                mov     rax, [rbp-8]
                mov     edx, eax
                mov     rax, [rbp-38h]
                mov     [rax], dl
                jmp     short loc_4006E3

loc_size_2:
                mov     rax, [rbp-8]
                mov     edx, eax
                mov     rax, [rbp-38h]
                mov     [rax], dx
                jmp     short loc_4006E3

loc_size_4:
                mov     rax, [rbp-8]
                mov     edx, eax
                mov     rax, [rbp-38h]
                mov     [rax], edx
                jmp     short loc_4006E3

loc_size_8:
                mov     rdx, [rbp-8]
                mov     rax, [rbp-38h]
                mov     [rax], rdx
loc_4006E3:
                pop     rbp
                ret