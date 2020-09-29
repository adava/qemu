//
// Created by sina on 2020-09-29.
//
#include "asm_generation.h"
#ifndef QEMU_BIN_GEN_H
#define QEMU_BIN_GEN_H

#define CONCAT_HELPER_CODE "push    rbp;mov     rbp, rsp;mov     [rbp-18h], rdi;mov     [rbp-28h], rdx;mov     eax, ecx;\
                            mov     edx, r8d;mov     [rbp-38h], r9;mov     [rbp-1ch], si;mov     [rbp-20h], ax;mov     [rbp-2ch], dx;\
                            movzx   eax, word ptr [rbp-1ch];shl     eax, 3;mov     rdx, [rbp-28h];mov     ecx, eax;shl     rdx, cl;\
                            mov     rax, rdx;mov     [rbp-10h], rax;mov     rax, [rbp-18h];or      rax, [rbp-10h];mov     [rbp-8], rax;\
                            movzx   eax, word ptr [rbp-2ch];cmp     eax, 2;jz loc_size_2;cmp     eax, 2;jg loc_size_cmp;\
                            cmp     eax, 1;jz loc_size_1;jmp loc_4006E3;loc_size_cmp:cmp     eax, 4;jz loc_size_4;\
                            cmp     eax, 8;jz loc_size_8;jmp loc_4006E3;loc_size_1:mov     rax, [rbp-8];\
                            mov     edx, eax;mov     rax, [rbp-38h];mov     [rax], dl;jmp loc_4006E3;\
                            loc_size_2:mov     rax, [rbp-8];mov     edx, eax;mov     rax, [rbp-38h];mov     [rax], dx;\
                            jmp loc_4006E3;loc_size_4:mov     rax, [rbp-8];mov     edx, eax;mov     rax, [rbp-38h];\
                            mov     [rax], edx;jmp loc_4006E3;loc_size_8:mov     rdx, [rbp-8];mov     rax, [rbp-38h];\
                            mov     [rax], rdx;loc_4006E3:pop     rbp;ret;"

#define TRUNC_HELPER_CODE       "push    rbp;mov     rbp, rsp;mov     [rbp-18h], rdi;mov     eax, edx;mov     [rbp-28h], rcx;mov     [rbp-1Ch], si; \
                           mov     [rbp-20h], ax; movzx   eax, word ptr [rbp-20h];mov     edx, 8;sub     edx, eax;mov     eax, edx;shl     eax, 3; \
                           mov     rdx, [rbp-18h];mov     ecx, eax;shl     rdx, cl;mov     rax, rdx;mov     [rbp-10h], rax; \
                           movzx   eax, word ptr [rbp-20h];mov     edx, 8;sub     edx, eax;mov     eax, edx;shl     eax, 3; \
                           mov     rdx, [rbp-10h];mov     ecx, eax;shr     rdx, cl;mov     rax, rdx;mov     [rbp-8], rax; \
                           movzx   eax, word ptr [rbp-1Ch];cmp     eax, 2;jz      loc_40061B;cmp     eax, 2;jg      loc_400601; \
                           cmp     eax, 1;jz      loc_40060D;jmp     loc_400644;loc_400601:cmp     eax, 4;jz      loc_40062A; \
                           cmp     eax, 8;jz      loc_400638;jmp     loc_400644;loc_40060D:mov     rax, [rbp-8];mov     edx, eax; \
                           mov     rax, [rbp-28h];mov     [rax], dl;jmp    loc_400644;loc_40061B:mov     rax, [rbp-8];mov     edx, eax; \
                           mov     rax, [rbp-28h];mov     [rax], dx;jmp    loc_400644;loc_40062A:mov     rax, [rbp-8];mov     edx, eax; \
                           mov     rax, [rbp-28h];mov     [rax], edx;jmp    loc_400644;loc_400638:mov     rdx, [rbp-8];mov     rax, [rbp-28h]; \
                           mov     [rax], rdx;loc_400644:pop     rbp;ret;"

#define HELPERS CONCAT_HELPER_NAME":"CONCAT_HELPER_CODE""TRUNC_HELPER_NAME":"TRUNC_HELPER_CODE

#define SLICE_EXEC_FILE "asm_map"

void (*concat_func)(long long unsigned int op1,short unsigned int op1_size,long long unsigned int op2,short unsigned int op2_size,short unsigned int concat_size,void *retaddr);

void (*trunc_func)(long long unsigned int op,short unsigned int orig_size,short unsigned int trunc_size,void *retaddr);

typedef long unsigned int (*slice_func)(char *input, int num_bytes);

int initialize_executable_file(char *file_name);

void* assemble_and_write(unsigned char *encode, size_t *size, char *CODE);

void* executable_from_asm(char *asm_file, char **asm_code, int *asm_code_size, size_t *assembled_size);

#endif //QEMU_BIN_GEN_H
