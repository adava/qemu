//===-- dfsan.h -------------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Private DFSan header.
//===----------------------------------------------------------------------===//

#ifndef DFSAN_H
#define DFSAN_H
#include <errno.h>
#include <sys/file.h>
#include <sys/mman.h>
//#define GLOBAL_POOL_SIZE 254
#include "dfsan_platform.h"

#define Swap(type,a,b) \
{\
 type c=a; a=b; b=c;\
}

// Copy declarations from public sanitizer/dfsan_interface.h header here.
typedef uint16_t dfsan_label;

dfsan_label registers_shadow[GLOBAL_POOL_SIZE];

void internal_iserror(int retval, char *err);
void UnmapOrDie(void *addr, uint64_t size);
int GetNamedMappingFd(const char *name, uint32_t size, int *flags);
void *MmapNamed(void *addr, uint64_t length, int prot, int flags, const char *name);
static bool MmapFixed(uint64_t fixed_addr, uint64_t size, int additional_flags, const char *name);
bool MmapFixedNoReserve(uint64_t fixed_addr, uint64_t size, const char *name);
void *MmapFixedNoAccess(uint64_t fixed_addr, uint64_t size, const char *name);
static inline dfsan_label *shadow_for(const void *ptr);

void internal_iserror(int retval, char *err) {
    if (retval < 0) {
        if (errno)
            perror(err);
    }
    assert(retval>=0);
}


//dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2);
//dfsan_label dfsan_create_label(const char *desc, void *userdata);
//void dfsan_set_label(dfsan_label label, void *addr, uint64_t size);
//void dfsan_add_label(dfsan_label label, void *addr, uint64_t size);
//dfsan_label dfsan_read_label(const void *addr, uint64_t size);
//void dfsan_add_label(dfsan_label label, void *addr, uint64_t size);
//void dfsan_set_label(dfsan_label label, void *addr, uint64_t size);
//dfsan_label dfsan_read_label(const void *addr, uint64_t size);
//dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2);

#endif  // DFSAN_H
