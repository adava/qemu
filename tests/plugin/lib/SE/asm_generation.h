//
// Created by sina on 2020-09-18.
//
#ifndef ASM_GEN_H
#define ASM_GEN_H
#include "defs.h"
#define CONCAT_HELPER_NAME "concat_func" //this should be here but the acutall helper logic could be moved to the bin_gen
#define TRUNC_HELPER_NAME "truncate_func" //this should be here but the acutall helper logic could be moved to the bin_gen
#define SLICE_PROLOGUE      "sub rsp, rsi\nxor rcx, rcx\nxor al, al\nCopy_input:\ncmp rsi, rcx\nje  Slice_code\ninc rdi\ninc rsp\nmov al, byte ptr [rdi-1]\nmov byte ptr [rsp-1], al\ninc rcx\njmp Copy_input\nSlice_code:\n"
#define SLICE_EPILOGUE      "ret\n" //the movement of return value to EAX has been put in slice body
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

#define HELPER_CONCAT CONCAT_HELPER_NAME":\n"CONCAT_HELPER_CODE

#define HELPER_TRUNC TRUNC_HELPER_NAME":\n"TRUNC_HELPER_CODE

#define HELPERS HELPER_CONCAT"\n"HELPER_TRUNC
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

void generate_asm_body(int root);

void print_asm_slice_function(const char *file_name);

void dfsan_graphviz(dfsan_label root, char *graph_file);

#endif