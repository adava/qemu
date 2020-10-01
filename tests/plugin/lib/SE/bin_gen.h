//
// Created by sina on 2020-09-29.
//
#include "asm_generation.h"
#ifndef QEMU_BIN_GEN_H
#define QEMU_BIN_GEN_H

#define CONCAT_HELPER_CODE "push    rbp\nmov     rbp, rsp\nmov     [rbp-18h], rdi\nmov     [rbp-28h], rdx\nmov     eax, ecx\n \
                            mov     edx, r8d\nmov     [rbp-38h], r9\nmov     [rbp-1ch], si\nmov     [rbp-20h], ax\nmov     [rbp-2ch], dx\n \
                            movzx   eax, word ptr [rbp-1ch]\nshl     eax, 3\nmov     rdx, [rbp-28h]\nmov     ecx, eax\nshl     rdx, cl\n \
                            mov     rax, rdx\nmov     [rbp-10h], rax\nmov     rax, [rbp-18h]\nor      rax, [rbp-10h]\nmov     [rbp-8], rax\n \
                            movzx   eax, word ptr [rbp-2ch]\ncmp     eax, 2\njz loc_size_2\ncmp     eax, 2\njg loc_size_cmp\n \
                            cmp     eax, 1\njz loc_size_1\njmp loc_4006E3\nloc_size_cmp:cmp     eax, 4\njz loc_size_4\n \
                            cmp     eax, 8\njz loc_size_8\njmp loc_4006E3\nloc_size_1:mov     rax, [rbp-8]\n \
                            mov     edx, eax\nmov     rax, [rbp-38h]\nmov     [rax], dl\njmp loc_4006E3\n \
                            loc_size_2:mov     rax, [rbp-8]\nmov     edx, eax\nmov     rax, [rbp-38h]\nmov     [rax], dx\n \
                            jmp loc_4006E3\nloc_size_4:mov     rax, [rbp-8]\nmov     edx, eax\nmov     rax, [rbp-38h]\n \
                            mov     [rax], edx\njmp loc_4006E3\nloc_size_8:mov     rdx, [rbp-8]\nmov     rax, [rbp-38h]\n \
                            mov     [rax], rdx\nloc_4006E3:pop     rbp\nret\n"

#define TRUNC_HELPER_CODE       "push    rbp\nmov     rbp, rsp\nmov     [rbp-18h], rdi\nmov     eax, edx\nmov     [rbp-28h], rcx\nmov     [rbp-1Ch], si\n \
                           mov     [rbp-20h], ax\n movzx   eax, word ptr [rbp-20h]\nmov     edx, 8\nsub     edx, eax\nmov     eax, edx\nshl     eax, 3\n \
                           mov     rdx, [rbp-18h]\nmov     ecx, eax\nshl     rdx, cl\nmov     rax, rdx\nmov     [rbp-10h], rax\n \
                           movzx   eax, word ptr [rbp-20h]\nmov     edx, 8\nsub     edx, eax\nmov     eax, edx\nshl     eax, 3\n \
                           mov     rdx, [rbp-10h]\nmov     ecx, eax\nshr     rdx, cl\nmov     rax, rdx\nmov     [rbp-8], rax\n \
                           movzx   eax, word ptr [rbp-1Ch]\ncmp     eax, 2\njz      loc_40061B\ncmp     eax, 2\njg      loc_400601\n \
                           cmp     eax, 1\njz      loc_40060D\njmp     loc_400644\nloc_400601:cmp     eax, 4\njz      loc_40062A\n \
                           cmp     eax, 8\njz      loc_400638\njmp     loc_400644\nloc_40060D:mov     rax, [rbp-8]\nmov     edx, eax\n \
                           mov     rax, [rbp-28h]\nmov     [rax], dl\njmp    loc_400644\nloc_40061B:mov     rax, [rbp-8]\nmov     edx, eax\n \
                           mov     rax, [rbp-28h]\nmov     [rax], dx\njmp    loc_400644\nloc_40062A:mov     rax, [rbp-8]\nmov     edx, eax\n \
                           mov     rax, [rbp-28h]\nmov     [rax], edx\njmp    loc_400644\nloc_400638:mov     rdx, [rbp-8]\nmov     rax, [rbp-28h]\n \
                           mov     [rax], rdx\nloc_400644:pop     rbp\nret\n"

#define HELPERS CONCAT_HELPER_NAME":"CONCAT_HELPER_CODE""TRUNC_HELPER_NAME":"TRUNC_HELPER_CODE

#define SLICE_EXEC_FILE "asm_map"

void (*concat_func)(long long unsigned int op1,short unsigned int op1_size,long long unsigned int op2,short unsigned int op2_size,short unsigned int concat_size,void *retaddr);

void (*trunc_func)(long long unsigned int op,short unsigned int orig_size,short unsigned int trunc_size,void *retaddr);

typedef long unsigned int (*slice_func)(char *input, int num_bytes);

int initialize_executable_file(char *file_name);

void* assemble_and_write(unsigned char *encode, size_t *size, char *CODE);

void* executable_from_asm(char *asm_file, char **asm_code, int *asm_code_size, size_t *assembled_size);

#endif //QEMU_BIN_GEN_H
