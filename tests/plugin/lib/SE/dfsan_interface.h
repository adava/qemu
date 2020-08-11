//===-- dfsan_interface.h -------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Public interface header.
//===----------------------------------------------------------------------===//
#ifndef DFSAN_INTERFACE_H
#define DFSAN_INTERFACE_H

#include <stddef.h>
#include <stdint.h>
#include "defs.h"

#define dfsan_set_register_label(reg, label) \
        assert(reg<GLOBAL_POOL_SIZE); \
        registers_shadow[reg]=label;

#define dfsan_get_register_label(reg) reg<GLOBAL_POOL_SIZE?registers_shadow[reg]:-1

#ifdef __cplusplus
extern "C" {
#endif

/// Stores information associated with a specific label identifier.  A label
/// may be a base label created using dfsan_create_label, with associated
/// text description and user data, or an automatically created union label,
/// which represents the union of two label identifiers (which may themselves
/// be base or union labels).

/// Computes the union of \c l1 and \c l2, possibly creating a union label in
/// the process.

dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, u16 op, u8 size, u64 op1, u64 op2, u8 op1_type, u8 op2_type, u64 dest, u8 dest_type);

//dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, u8 op, u8 size);

/// Creates and returns a base label with the given description and user data.
dfsan_label dfsan_create_label(int pos);

/// Sets the label for each address in [addr,addr+size) to \c label.
void dfsan_set_label(dfsan_label label, void *addr, size_t size);

/// Sets the label for each address in [addr,addr+size) to the union of the
/// current label for that address and \c label.
void dfsan_add_label(dfsan_label label, u8 op, void *addr, size_t size);

/// Retrieves the label associated with the given data.
///
/// The type of 'data' is arbitrary.  The function accepts a value of any type,
/// which can be truncated or extended (implicitly or explicitly) as necessary.
/// The truncation/extension operations will preserve the label of the original
/// value.
dfsan_label dfsan_get_label(long data);

/// Retrieves the label associated with the data at the given address.
dfsan_label dfsan_read_label(const void *addr, size_t size);

/// Retrieves the starting address for the shadow memory of the given address
const dfsan_label *dfsan_shadow_for(const void * addr);

/// Retrieves a pointer to the dfsan_label_info struct for the given label.
const dfsan_label_info *dfsan_get_label_info(dfsan_label label);

/// Returns whether the given label label contains the label elem.
int dfsan_has_label(dfsan_label label, dfsan_label elem);

/// If the given label label contains a label with the description desc, returns
/// that label, else returns 0.
dfsan_label dfsan_has_label_with_desc(dfsan_label label, const char *desc);

/// Returns the number of labels allocated.
size_t dfsan_get_label_count(void);

/// Flushes the DFSan shadow, i.e. forgets about all labels currently associated
/// with the application memory. Will work only if there are no other
/// threads executing DFSan-instrumented code concurrently.
/// Use this call to start over the taint tracking within the same procces.
void dfsan_flush(void);

/// Writes the labels currently used by the program to the given file
/// descriptor. The lines of the output have the following format:
///
/// <label> <parent label 1> <parent label 2> <label description if any>
void dfsan_dump_labels(int fd);


//static inline dfsan_label *shadow_for(const void *ptr);

void mark_input_bytes(void *addr, int64_t ret, uint8_t value);

void dfsan_init(void);

void dfsan_fini(void);

#ifdef __cplusplus
}  // extern "C"

template <typename T>
void dfsan_set_label(dfsan_label label, T &data) {  // NOLINT
  dfsan_set_label(label, (void *)&data, sizeof(T));
}

#endif

#endif  // DFSAN_INTERFACE_H
