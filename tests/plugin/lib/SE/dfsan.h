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

#include "./sanitizer_common/sanitizer_internal_defs.h"

#include <sys/file.h>
#include <sys/mman.h>
#define GLOBAL_POOL_SIZE 254
#include "dfsan_platform.h"
#include "shadow_memory.h"
#include <stdio.h>
#include <inttypes.h>

#ifdef SANITIZER_CAN_USE_PREINIT_ARRAY //can't be used in the Qemu pluging environment
#undef SANITIZER_CAN_USE_PREINIT_ARRAY
#endif

//#define Swap(type,a,b) \
//{\
// type c=a; a=b; b=c;\
//}

// Copy declarations from public sanitizer/dfsan_interface.h header here.
typedef u32 dfsan_label;


#define B_FLIPPED 0x1

#ifndef PATH_MAX
# define PATH_MAX 4096
#endif

typedef int shadow_err;

extern "C" {
void dfsan_add_label(dfsan_label label, u8 op, void *addr, uptr size);
void dfsan_set_label(dfsan_label label, void *addr, uptr size);
dfsan_label dfsan_read_label(const void *addr, uptr size);
void dfsan_store_label(dfsan_label l1, void *addr, uptr size);
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, u16 op, u8 size, u64 op1, u64 op2, u8 op1_type, u8 op2_type, u64 dest, u8 dest_type);
dfsan_label dfsan_create_label(off_t offset);
dfsan_label dfsan_get_label(const void *addr);

void dfsan_init(guest_memory_read_func func);
// taint source
void mark_input_bytes(void *addr, int64_t ret, uint8_t value);

void dfsan_fini(char *lfile);

}  // extern "C"

template <typename T>
void dfsan_set_label(dfsan_label label, T &data) {  // NOLINT
    dfsan_set_label(label, (void *)&data, sizeof(T));
}

namespace __dfsan {

//    dfsan_label *shadow_for(void *ptr) { //sina: this new implementation might result in collision e.g. one address falling below the shadow memory area and one above.
//        uint64_t index = ((((uint64_t) ptr) & ShadowMask()) << 1); //it should be left shift by 2 since the new dfsan_label is 4 bytes
//        return (dfsan_label *)((uint64_t)shadow_start + index);
//    }

    dfsan_label *shadow_for(void *ptr) {
        return (dfsan_label *)get_shadow_memory((uint64_t)ptr);
    }


    inline const dfsan_label *shadow_for(const void *ptr) {
        return shadow_for(const_cast<void *>(ptr));
    }

    inline void *app_for(const dfsan_label *l) {
        return (void *) ((((uptr) l) >> 2) | AppBaseAddr());
    }

    static inline bool is_commutative(u16 op) { //sina: not very meaningful in the binary analysis context; Add EAX, ECX is not equivalent to ADD ECX, EAX because their destinations are different.
        switch(op) {                                      //but since we separately store the destination, it wouldn't harm to reorder the sources.
            case Not:
            case And:
            case Or:
            case Xor:
            case Add:
            case Mul:
            case Adc:
                return true;
            default:
                return false;
        }
    }

}  // namespace __dfsan

//void internal_iserror(int retval, char *err);
//void UnmapOrDie(void *addr, uint64_t size);
//int GetNamedMappingFd(const char *name, uint32_t size, int *flags);
//void *MmapNamed(void *addr, uint64_t length, int prot, int flags, const char *name);
//static bool MmapFixed(uint64_t fixed_addr, uint64_t size, int additional_flags, const char *name);
//bool MmapFixedNoReserve(uint64_t fixed_addr, uint64_t size, const char *name);
//void *MmapFixedNoAccess(uint64_t fixed_addr, uint64_t size, const char *name);


//dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2);
//dfsan_label dfsan_create_label(const char *desc, void *userdata);
//void dfsan_set_label(dfsan_label label, void *addr, uint64_t size);
//void dfsan_add_label(dfsan_label label, void *addr, uint64_t size);
//dfsan_label dfsan_read_label(const void *addr, uint64_t size);
//void dfsan_add_label(dfsan_label label, void *addr, uint64_t size);
//void dfsan_set_label(dfsan_label label, void *addr, uint64_t size);
//dfsan_label dfsan_read_label(const void *addr, uint64_t size);
//dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2);
//static inline dfsan_label *shadow_for(const void *ptr);
//static void mark_input_bytes(uint64_t *addr, int64_t ret, uint8_t value);

#endif  // DFSAN_H
