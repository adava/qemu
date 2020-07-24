//
// Created by sina on 2020-07-22.
//

#ifndef _HAVE_DEFS_H
#define _HAVE_DEFS_H

#include <stdint.h>
#include <stdlib.h>

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

enum operators { //sina: revise based on capstone
    Not       = 1,
    Neg       = 2,
    And,
    Or,
    Xor,
    Add,
    Mul,
    Load, /* from here after, the use is internal in the Load/Store */
    Extract, //sina: a label union with constants copied to a series of bytes
    Concat, //sina: concat of labels and others (label or constant)
    Trunc,  //sina: Truncate a label because only a portion of it will be loaded
    ZExt, //sina:? Zero Extension
};

typedef struct dfsan_label_info {
    dfsan_label l1;
    dfsan_label l2;
    u64 op1;
    u64 op2;
    u16 op;
    u16 size;
    u8 flags;
    u32 tree_size;
    u32 hash;
    void* expr;
    void* deps;
} __attribute__((aligned (8))) dfsan_label_info;

dfsan_label registers_shadow[GLOBAL_POOL_SIZE];

#endif /* ! _HAVE_DEFS_H */
