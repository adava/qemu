//
// Created by sina on 2020-07-22.
//

#ifndef _HAVE_DEFS_H
#define _HAVE_DEFS_H

#include "../../../../capstone/include/x86.h" //sina: replace with the instruction set location
#include <stdint.h>
#include <stdlib.h>

#if 1
# define AOUT(...)
#else
# define AOUT(...)                                       \
  do {                                                  \
    if (1)  {                                           \
      printf("[RT] (%s:%d) ", __FUNCTION__, __LINE__);  \
      printf(__VA_ARGS__);                              \
    }                                                   \
  } while(false)
#endif

#define CONST_OFFSET 1
#define CONST_LABEL 0

#define op_start_id X86_INS_ENDING + 1 //sina: change to the starting ID to avoid conflict with the ISA

typedef unsigned long uptr;
typedef uint32_t dfsan_label;

//taken from namespace __sanitizer
typedef unsigned char u8;
typedef unsigned short u16;  // NOLINT
typedef unsigned int u32;
typedef unsigned long long u64;  // NOLINT
typedef signed   char s8;
typedef signed   short s16;  // NOLINT
typedef signed   int s32;
typedef signed   long long s64;  // NOLINT

enum shadow_type{
    UNASSIGNED = 0,
    TEMP = 1, //so we can distinguish uninitialized inquiries
    GLOBAL, //Register
    GLOBAL_IMPLICIT,
    MEMORY,
    MEMORY_IMPLICIT, //for instance Add mem, imm
    IMMEDIATE, //used for SHIFT, this type MUST not be passed to the shadow storage
//    FLAG, //modeled as part of GLOBAL
    MULTIPLE_OPS,
    EFFECTIVE_ADDR,
};

enum operators { //sina: based on capstone capstone/include/x86.h, revise based on the target arch/disassembler
    Not = X86_INS_NOT,
    Neg = X86_INS_NEG,
    And = X86_INS_AND,
    Or  = X86_INS_OR,
    Xor = X86_INS_XOR,
    Mul = X86_INS_MUL,
    Add = X86_INS_ADD,
    Adc = X86_INS_ADC,
    Load = op_start_id, /* from here after, the use is internal in the Load/Store */
    Load_REG,
    Extract, //sina: a label union with constants copied to a series of bytes
    Concat, //sina: concat of labels and others (label or constant)
    Trunc,  //sina: Truncate a label because only a portion of it will be loaded
    ZExt, //sina:? Zero Extension; movzx and movsxd in the binary
    Nop, //a non-cumulative operation to model Valgrind union
    UNION_MULTIPLE_OPS,
    EFFECTIVE_ADDR_UNION,
    TAINT,
    op_end_id
};

typedef struct dfsan_label_info {
    dfsan_label l1;
    dfsan_label l2;
    u64 op1;
    enum shadow_type op1_type;
    u64 op2;
    enum shadow_type op2_type;
    u64 dest;
    enum shadow_type dest_type;
    u16 op;
    u16 size;
    u8 flags;
    u32 tree_size;
    u32 hash;
//    void* expr;
//    void* deps;
} __attribute__((aligned (8))) dfsan_label_info;

dfsan_label registers_shadow[GLOBAL_POOL_SIZE];

typedef void (*guest_memory_read_func)(uint64_t vaddr, int len, void *buf);

typedef void (*guest_registers_read_func)(uint32_t reg, int len, void *buf);

typedef const char*(*print_instruction)(dfsan_label_info *label);

typedef struct dfsan_settings{
    guest_memory_read_func readFunc;
    guest_registers_read_func regValue;
    print_instruction printInst;
} dfsan_settings;


//print_instruction operator_printers[op_end_id-op_start_id];

#endif /* ! _HAVE_DEFS_H */
