//
// Created by sina on 2020-09-18.
//
#ifndef ASM_GEN_H
#define ASM_GEN_H
#include "defs.h"
#define CONCAT_HELPER_NAME "concat_func" //this should be here but the acutall helper logic could be moved to the bin_gen
#define TRUNC_HELPER_NAME "truncate_func" //this should be here but the acutall helper logic could be moved to the bin_gen
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

typedef struct {
    u64 operand;
    enum shadow_type type;
    void *label; //the memory placeholder for the value, needed for operand initialization
    u16 size;
} asm_operand;

typedef struct {
    asm_operand operands[8];
    u8 num_operands;
} multiple_operands; //would be assigned to a UNION_MULTIPLE_OPS

//void *callHelperTruncate(u64 operand, u16 orig_size, u16 trunc_size);
//
//void *callHelperConcat(u64 op1, u16 op1_size, u64 op2, u16 op2_size,u16 concat_size);

void generate_asm(int root);

void generate_asm_func(int root);

void dfsan_graphviz(dfsan_label root, char *graph_file);

#endif