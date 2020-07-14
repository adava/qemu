//===-- dfsan_platform.h ----------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Platform specific information for DFSan.
//===----------------------------------------------------------------------===//

#ifndef DFSAN_PLATFORM_H
#define DFSAN_PLATFORM_H

typedef enum MappingType {
    MAPPING_SHADOW_ADDR,
    MAPPING_UNION_TABLE_ADDR,
    MAPPING_APP_ADDR,
    MAPPING_SHADOW_MASK
} MappingType;

static const uint64_t kShadowAddr = 0x10000;
static const uint64_t kUnionTableAddr = 0x200000000000;
static const uint64_t kAppAddr = 0x700000008000;
static const uint64_t kShadowMask = ~0x700000000000;

uint64_t MappingImpl(MappingType Type);
uint64_t ShadowAddr(void);
uint64_t UnionTableAddr(void);
uint64_t AppAddr(void);
uint64_t ShadowMask(void);

uint64_t MappingImpl(MappingType Type) {
    switch (Type) {
        case MAPPING_SHADOW_ADDR: return kShadowAddr;
        case MAPPING_UNION_TABLE_ADDR: return kUnionTableAddr;
        case MAPPING_APP_ADDR: return kAppAddr;
        case MAPPING_SHADOW_MASK: return kShadowMask;
        default:
            assert(0);
    }
}

inline uint64_t ShadowAddr(void) {
    return MappingImpl(MAPPING_SHADOW_ADDR);
}

inline uint64_t UnionTableAddr(void) {
    return MappingImpl(MAPPING_UNION_TABLE_ADDR);
}

inline uint64_t AppAddr(void) {
    return MappingImpl(MAPPING_APP_ADDR);
}

inline uint64_t ShadowMask(void) {
    return MappingImpl(MAPPING_SHADOW_MASK);
}


#endif
