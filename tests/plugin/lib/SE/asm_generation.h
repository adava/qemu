//
// Created by sina on 2020-09-18.
//
#ifndef ASM_GEN_H
#define ASM_GEN_H
#include "defs.h"
#define CONCAT_HELPER_NAME "concat_func" //this should be here but the acutall helper logic could be moved to the bin_gen
#define TRUNC_HELPER_NAME "truncate_func" //this should be here but the acutall helper logic could be moved to the bin_gen

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