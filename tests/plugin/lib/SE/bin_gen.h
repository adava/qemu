//
// Created by sina on 2020-09-29.
//
#include "asm_generation.h"
#ifndef QEMU_BIN_GEN_H
#define QEMU_BIN_GEN_H

#define SLICE_EXEC_FILE "asm_map"

void (*concat_func)(long long unsigned int op1,short unsigned int op1_size,long long unsigned int op2,short unsigned int op2_size,short unsigned int concat_size,void *retaddr);

void (*trunc_func)(long long unsigned int op,short unsigned int orig_size,short unsigned int trunc_size,void *retaddr);

typedef long unsigned int (*slice_func)(char *input, int num_bytes);

int initialize_executable_file(char *file_name);

void* assemble_and_write(unsigned char *encode, size_t *size, char *CODE);

void* executable_from_asm(char *asm_file, char **asm_code, int *asm_code_size, size_t *assembled_size);

#endif //QEMU_BIN_GEN_H
