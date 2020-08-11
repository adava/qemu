//===-- dfsan.cc ----------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// DataFlowSanitizer runtime.  This file defines the public interface to
// DataFlowSanitizer as well as the definition of certain runtime functions
// called automatically by the compiler (specifically the instrumentation pass
// in llvm/lib/Transforms/Instrumentation/DataFlowSanitizer.cpp).
//
// The public interface is defined in include/sanitizer/dfsan_interface.h whose
// functions are prefixed dfsan_ while the compiler interface functions are
// prefixed __dfsan_.
//===----------------------------------------------------------------------===//
#include "dfsan.h"

#include "./sanitizer_common/sanitizer_atomic.h"
#include "./sanitizer_common/sanitizer_common.h"

#include <sys/time.h>
#include <sys/resource.h>

#include "taint_allocator.h"
#include "union_util.h"
#include "union_hashtable.h"

//#include "taint_allocator.cc"
//#include "union_util.cc"
//#include "union_hashtable.cc"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#define OPTIMISTIC 1
#define kNumLabels  (1 << (sizeof(dfsan_label) * 8))

using namespace __dfsan;

typedef atomic_uint32_t atomic_dfsan_label;
static const dfsan_label kInitializingLabel = -1;
const char *dump_labels_at_exit = "dfsan_labels.txt";

static atomic_dfsan_label __dfsan_last_label;
static dfsan_label_info *__dfsan_label_info;

// Hash table
static const uptr hashtable_size = (1ULL << 32);
static const size_t union_table_size = (1ULL << 18);
static __taint::union_hashtable __union_table(union_table_size);

// for output
static u32 __current_index = 0;

// On Linux/x86_64, memory is laid out as follows:
//
// +--------------------+ 0x800000000000 (top of memory)
// | application memory |
// +--------------------+ 0x700000040000 (kAppAddr)
// |--------------------| UnusedAddr()
// |                    |
// |    hash table      |
// |                    |
// +--------------------+ 0x4000c0000000 (kHashTableAddr)
// |    union table     |
// +--------------------+ 0x400000000000 (kUnionTableAddr)
// |   shadow memory    |
// +--------------------+ 0x000000100000 (kShadowAddr)
// |       unused       |
// +--------------------+ 0x000000010000 (kKernelAddr)
// | reserved by kernel |
// +--------------------+ 0x000000000000
//
// To derive a shadow memory address from an application memory address,
// bits 44-46 are cleared to bring the address into the range    //44-46 are fixed for all app addressed (representing 7 and then 8 is next addr)
// [0x000000008000,0x100000000000).  Then the address is shifted left by 2 to
// account for the 4 bytes representation of shadow labels and move the //each shadow address would store a 32 bit ID, hence 4 byte representation
// address into the shadow memory range.  See the function shadow_for below.

#ifdef DFSAN_RUNTIME_VMA
// Runtime detected VMA size.
int __dfsan::vmaSize;
#endif


static uptr UnusedAddr() {
  return MappingArchImpl<MAPPING_HASH_TABLE_ADDR>() + hashtable_size;
}

// Checks we do not run out of labels.
static void dfsan_check_label(dfsan_label label) {
  if (label == kInitializingLabel) {
    printf("FATAL: Taint: out of labels\n");
    Die();
  } else if ((uptr)(&__dfsan_label_info[label]) >= HashTableAddr()) {
    printf("FATAL: Exhausted labels\n");
    Die();
  }
}

// based on https://github.com/Cyan4973/xxHash
// simplified since we only have 12 bytes info
static inline u32 xxhash(u32 h1, u32 h2, u32 h3) {
  const u32 PRIME32_1 = 2654435761U;
  const u32 PRIME32_2 = 2246822519U;
  const u32 PRIME32_3 = 3266489917U;
  const u32 PRIME32_4 =  668265263U;
  const u32 PRIME32_5 =  374761393U;

  #define XXH_rotl32(x,r) ((x << r) | (x >> (32 - r)))
  u32 h32 = PRIME32_5;
  h32 += h1 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  h32 += h2 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  h32 += h3 * PRIME32_3;
  h32  = XXH_rotl32(h32, 17) * PRIME32_4;
  #undef XXH_rotl32

  h32 ^= h32 >> 15;
  h32 *= PRIME32_2;
  h32 ^= h32 >> 13;
  h32 *= PRIME32_3;
  h32 ^= h32 >> 16;

  return h32;
}

static inline dfsan_label_info* get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

static inline bool is_constant_label(dfsan_label label) {
  return label == CONST_LABEL;
}

static inline bool is_kind_of_label(dfsan_label label, u16 kind) {
  return get_label_info(label)->op == kind;
}

static bool isZeroOrPowerOfTwo(uint16_t x) { return (x & (x - 1)) == 0; }

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
const dfsan_label * dfsan_shadow_for(const void * addr){
    return shadow_for(addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_union(dfsan_label l1, dfsan_label l2, u16 op, u16 size,
                          u64 op1, u64 op2, enum shadow_type op1_type, enum shadow_type op2_type, u64 dest, enum shadow_type dest_type) {
//  if (l1 > l2 && is_commutative(op)) { //sina: not sure whether this should be kept; in the binary generation, we might run to some problems. Swapping also the dest might work but not sure what the implications will be in this stage!
//    // needs to swap both labels and concretes
//    Swap(l1, l2);
//    Swap(op1, op2);
//  }
  if (l1 == 0 && l2 < CONST_OFFSET /*&& op != fsize*/) return 0; //sina: no fsize at the moment
  if (l1 == kInitializingLabel || l2 == kInitializingLabel) return kInitializingLabel;

  if (l1 >= CONST_OFFSET) op1 = 0;
  if (l2 >= CONST_OFFSET) op2 = 0;

  struct dfsan_label_info label_info = {
    .l1 = l1, .l2 = l2, .op1 = op1, .op1_type=op1_type , .op2 = op2, .op2_type = op2_type, .dest = dest, .dest_type = dest_type, .op = op, .size = size,
    .flags = 0, .tree_size = 0, .hash = 0, .expr = nullptr, .deps = nullptr};

  __taint::option res = __union_table.lookup(label_info);
  if (res != __taint::none()) {
    dfsan_label label = *res;
    AOUT("%u found\n", label);
    return label;
  }
  // for debugging
  dfsan_label l = atomic_load(&__dfsan_last_label, memory_order_relaxed);
  assert(l1 <= l && l2 <= l);

  dfsan_label label =
    atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
  dfsan_check_label(label);
  assert(label > l1 && label > l2);

  AOUT("%u = (%u, %u, %u, %u, %llu, %llu)\n", label, l1, l2, op, size, op1, op2);

  // setup a hash tree for dedup
  u32 h1 = l1 ? __dfsan_label_info[l1].hash : 0;
  u32 h2 = l2 ? __dfsan_label_info[l2].hash : 0;
  u32 h3 = op;
  h3 = (h3 << 16) | size;
  label_info.hash = xxhash(h1, h2, h3);

  memcpy(&__dfsan_label_info[label], &label_info, sizeof(dfsan_label_info));
  __union_table.insert(&__dfsan_label_info[label], label);
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_union_load(const void *addr,const dfsan_label *ls, uptr n) {
  dfsan_label label0 = ls[0];
  if (label0 == kInitializingLabel) return kInitializingLabel;

  // for debugging
  // dfsan_label l = atomic_load(&__dfsan_last_label, memory_order_relaxed);
  // assert(label0 <= l);
  if (label0 >= CONST_OFFSET) assert(get_label_info(label0)->size != 0);

  // fast path 1: constant
  if (is_constant_label(label0)) {
    bool constant = true;
    for (uptr i = 1; i < n; i++) {
      if (!is_constant_label(ls[i])) {
        constant = false;
        break;
      }
    }
    if (constant) return CONST_LABEL;
  }
  AOUT("label0 = %d, n = %d, ls = %p\n", label0, n, ls);
  // shape
  bool shape = true;
  uptr shape_ext = 0;
  if (__dfsan_label_info[label0].op != 0) {
    // not raw input bytes
    shape = false;
  } else {
    off_t offset = get_label_info(label0)->op1;
    for (uptr i = 1; i != n; ++i) {
      dfsan_label next_label = ls[i];
      if (next_label == kInitializingLabel) return kInitializingLabel; //sina: ran out of labels
      else if (next_label == CONST_LABEL) ++shape_ext;
      else if (get_label_info(next_label)->op1 != offset + i) {
        shape = false;
        break;
      }
    }
  }
  if (shape) {
    if (n == 1) return label0;

    uptr load_size = n - shape_ext; //exclude the constants

    AOUT("shape: label0: %d %d %d\n", label0, load_size, n);

    dfsan_label ret = label0;
    if (load_size > 1) {
      ret = __taint_union(label0, (dfsan_label)load_size, Load, load_size * 8, 0, 0, UNASSIGNED, UNASSIGNED, 0, UNASSIGNED);
    }
    if (shape_ext) {
      for (uptr i = 0; i < shape_ext; ++i) {
//        char *c = (char *)app_for(&ls[load_size + i]);  //sina: we should make sure app_for() would take us to the guest memory from the shadow address; with the current mapping flaw, this is not possible (collision)
        char *c = (char *)(addr+load_size + i); //not sure if it works
        ret = __taint_union(ret, 0, Concat, (load_size + i + 1) * 8, 0, *c,UNASSIGNED,IMMEDIATE,0,UNASSIGNED);  //sina: keeping track of the constants, and storing them
      }
    }
    return ret;
  }

  // fast path 2: all labels are extracted from a n-size label, then return that label
  if (is_kind_of_label(label0, Extract)) {
    dfsan_label parent = get_label_info(label0)->l1;
    uptr offset = 0;
    for (uptr i = 0; i < n; i++) {
      dfsan_label_info *info = get_label_info(ls[i]);
      if (!is_kind_of_label(ls[i], Extract)
            || offset != info->op2
            || parent != info->l1) {
        break;
      }
      offset += info->size;
    }
    if (get_label_info(parent)->size == offset) {
      AOUT("Fast path (2): all labels are extracts: %u\n", parent);
      return parent;
    }
  }

  // slowpath
  AOUT("union load slowpath at %p\n", __builtin_return_address(0));
  dfsan_label label = label0;
  for (uptr i = get_label_info(label0)->size / 8; i < n;) {
    dfsan_label next_label = ls[i];
    u16 next_size = get_label_info(next_label)->size;
    AOUT("next label=%u, size=%u\n", next_label, next_size);
    if (!is_constant_label(next_label)) {
      if (next_size <= (n - i) * 8) {
        i += next_size / 8;
        label = __taint_union(label, next_label, Concat, i * 8, 0, 0, UNASSIGNED, UNASSIGNED, 0, UNASSIGNED); //sina: this might be a problem; the operands are not set
      } else {
        printf("WARNING: partial loading expected=%d has=%d\n", n-i, next_size);
        uptr size = n - i;
        dfsan_label trunc = __taint_union(next_label, CONST_LABEL, Trunc, size * 8, 0, 0, UNASSIGNED, UNASSIGNED, 0, UNASSIGNED);
        return __taint_union(label, trunc, Concat, n * 8, 0, 0, UNASSIGNED, UNASSIGNED, 0, UNASSIGNED);
      }
    } else {
      printf("WARNING: taint mixed with concrete %d\n", i);
      char *c = (char *)app_for(&ls[i]); //sina: instead of app_for, Qemu guest memory API should be called.
      ++i;
      label = __taint_union(label, 0, Concat, i * 8, 0, *c, UNASSIGNED, IMMEDIATE, 0, UNASSIGNED);
    }
  }
  AOUT("\n");
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_union_store(dfsan_label l, dfsan_label *ls, uptr n) {
  //AOUT("label = %d, n = %d, ls = %p\n", l, n, ls);
  if (l != kInitializingLabel) {
    // for debugging
    dfsan_label h = atomic_load(&__dfsan_last_label, memory_order_relaxed);
    assert(l <= h);
  } else {
    for (uptr i = 0; i < n; ++i)
      ls[i] = l;
    return;
  }

  // fast path 1: constant
  if (l == 0) { //sina: 0 is the value for the constant_label
    for (uptr i = 0; i < n; ++i)
      ls[i] = l;
    return;
  }

  dfsan_label_info *info = get_label_info(l);
  // fast path 2: single byte
  if (n == 1 && info->size == 8) { //info->size is stored in bits
    ls[0] = l;
    return;
  }

  // fast path 3: load
  if (is_kind_of_label(l, Load)) { //sina: seems for load, we store the size of the load as the value for l2; see the next comment
    // if source label is union load, just break it up
    dfsan_label label0 = info->l1;
    if (n > info->l2) { //sina: here, we compare l2 value with n that is the store size!
      printf("WARNING: store size=%u larger than load size=%d\n", n, info->l2);
    }
    for (uptr i = 0; i < n; ++i)
      ls[i] = label0 + i;
    return;
  }

  // fast path 4: Concat
  if (is_kind_of_label(l, Concat)) {
    if (n * 8 == info->size) {
      dfsan_label cur = info->l2; // next label
      dfsan_label_info* cur_info = get_label_info(cur);
      // store current
      __taint_union_store(info->l2, &ls[n - cur_info->size / 8], cur_info->size / 8);
      // store base
      __taint_union_store(info->l1, ls, n - cur_info->size / 8);
      return;
    }
  }

  // simplify
  if (is_kind_of_label(l, ZExt)) {
    dfsan_label orig = info->l1;
    // if the base size is multiple of byte
    if ((get_label_info(orig)->size & 0x7) == 0) {
      for (uptr i = get_label_info(orig)->size / 8; i < n; ++i)
        ls[i] = 0;
      __taint_union_store(orig, ls, get_label_info(orig)->size / 8); //sina: this line doesn't make sense; we would repeat the same operation in every iteration. Only ls elements would change that does not seem to affect the outcome
      return;
    }
  }

  // default fall through
  for (uptr i = 0; i < n; ++i) {
    ls[i] = __taint_union(l, CONST_LABEL, Extract, 8, 0, i * 8, IMMEDIATE, IMMEDIATE, 0, UNASSIGNED); //sina: so we use extract for label and a constant; the union is between two bytes, and we would record the offset from the start in the l2
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_store_label(dfsan_label l, void *addr, uptr size) {
  if (l == 0) return;
  __taint_union_store(l, shadow_for(addr), size);
}

// Like __dfsan_union, but for use from the client or custom functions.  Hence
// the equality comparison is done here before calling __dfsan_union.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2, u16 op, u8 size, u64 op1, u64 op2, u8 op1_type, u8 op2_type, u64 dest, u8 dest_type) {
  return __taint_union(l1, l2, op, size, op1, op2,(enum shadow_type)op1_type,(enum shadow_type)op2_type,dest,(enum shadow_type)dest_type);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label dfsan_create_label(off_t offset) {
  dfsan_label label =
    atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
  dfsan_check_label(label);
  memset(&__dfsan_label_info[label], 0, sizeof(dfsan_label_info));
  __dfsan_label_info[label].size = 8;
  // label may not equal to offset when using stdin
  __dfsan_label_info[label].op1 = offset;
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp) {
    // Don't write the label if it is already the value we need it to be.
    // In a program where most addresses are not labeled, it is common that
    // a page of shadow memory is entirely zeroed.  The Linux copy-on-write
    // implementation will share all of the zeroed pages, making a copy of a
    // page when any value is written.  The un-sharing will happen even if
    // the value written does not change the value in memory.  Avoiding the
    // write when both |label| and |*labelp| are zero dramatically reduces
    // the amount of real memory used by large programs.
    if (label == *labelp)
      continue;

    //AOUT("%p = %u\n", addr, label);
    *labelp = label;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  __dfsan_set_label(label, addr, size);
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_add_label(dfsan_label label, u8 op, void *addr, uptr size) {
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp)
    *labelp = __taint_union(*labelp, label, op, 1, 0, 0,UNASSIGNED,UNASSIGNED,0,UNASSIGNED);
}

// Unlike the other dfsan interface functions the behavior of this function
// depends on the label of one of its arguments.  Hence it is implemented as a
// custom function.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__dfsw_dfsan_get_label(long data, dfsan_label data_label,
                       dfsan_label *ret_label) {
  *ret_label = 0;
  return data_label;
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_read_label(const void *addr, uptr size) {
  if (size == 0)
    return 0;
  return __taint_union_load(addr,shadow_for(addr), size);
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_get_label(const void *addr) {
  return *shadow_for(addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
const struct dfsan_label_info *dfsan_get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_has_label(dfsan_label label, dfsan_label elem) { //sina: this is different than DFSan, here elem in l2 is part of label only if l1 is zero
  if (label == elem)
    return true;
  const dfsan_label_info *info = dfsan_get_label_info(label);
  if (info->l1 != 0) {
    return dfsan_has_label(info->l1, elem);
  }
  if (info->l2 != 0) {
    return dfsan_has_label(info->l2, elem);
  } 
  return false;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr
dfsan_get_label_count(void) {
  dfsan_label max_label_allocated =
      atomic_load(&__dfsan_last_label, memory_order_relaxed);

  return static_cast<uptr>(max_label_allocated);
}

shadow_err check_registers(uint64_t start, uint64_t end){
    assert(start<=end);
    assert(start<GLOBAL_POOL_SIZE);

    for(uint64_t i=start;i<=end;i++){
        dfsan_label label = registers_shadow[i];
        if (label!=0){
            return 2;
        }
    }
    return 0;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
mark_input_bytes(void *addr, int64_t ret, uint8_t value){
//    char *desc = malloc(20);
//    sprintf(desc,"%d",value);
    dfsan_label label = dfsan_create_label(value);
    for(int i=0;i<ret;i++){
        dfsan_set_label(label, addr+i, 1);
    }
//    printf("exiting mark_input\n");
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
dfsan_dump_labels(int fd) {
  dfsan_label last_label =
      atomic_load(&__dfsan_last_label, memory_order_relaxed);

  for (uptr l = 1; l <= last_label; ++l) {
    char buf[64];
    snprintf(buf, sizeof(buf), "%u %u %u ", l, __dfsan_label_info[l].l1, __dfsan_label_info[l].l2);
      write(fd, &(__dfsan_label_info[l].op1), sizeof(u64));
      write(fd, &(__dfsan_label_info[l].op2), sizeof(u64));
      write(fd, &(__dfsan_label_info[l].op), sizeof(u16));
      write(fd, "\n", 1);
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void dfsan_fini() {
    if (strcmp(dump_labels_at_exit, "") != 0) {
        int fd = open(dump_labels_at_exit, O_WRONLY);
        if (fd == -1) {
            printf("WARNING: DataFlowSanitizer: unable to open output file %s\n", dump_labels_at_exit);
            return;
        }

        printf("INFO: DataFlowSanitizer: dumping labels to %s\n", dump_labels_at_exit);
        dfsan_dump_labels(fd);
        //dump_shadows();
        close(fd);
    }

  // write output
  char *afl_shmid = getenv("__AFL_SHM_ID");
  if (afl_shmid) {
    u32 shm_id = atoi(afl_shmid);
    void *trace_id = shmat(shm_id, NULL, 0);
    *(reinterpret_cast<u32*>(trace_id)) = ++__current_index;
    shmdt(trace_id);
  }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void dfsan_init() {

    __dfsan::kShadowSize = MappingArchImpl<MAPPING_UNION_TABLE_ADDR>() - MappingArchImpl<MAPPING_SHADOW_ADDR>();
    __dfsan::kUnionTableSize = MappingArchImpl<MAPPING_HASH_TABLE_ADDR>() - MappingArchImpl<MAPPING_UNION_TABLE_ADDR>();
    __dfsan::kAllocationSize = kUnionTableSize + kShadowSize + hashtable_size;

//    printf("kShadowSize=%lx\tkUnionTableSize=%lx\tkAllocationSize=%lx\n",kShadowSize,kUnionTableSize,kAllocationSize);

    if (!MmapFixedNoReserve(ShadowAddr(), kAllocationSize, &shadow_start)) //0x1ffff0000 is the largest size I could try with fixed_addr
        assert(0);

//    printf("MmapFixedNoReserve 1 finished, shadow_start=%lx\n",shadow_start);

    __dfsan_label_info = (dfsan_label_info *)UnionTableAddr();

    // init const size
  __dfsan_label_info[CONST_LABEL].size = 8;

//  MmapFixedNoReserve(HashTableAddr(), hashtable_size); //sina: not sure about this

//    printf("UnionTableAddr=%lx\n",UnionTableAddr());
//    printf("HashTableAddr=%lx\n",HashTableAddr());


    __taint::allocator_init(HashTableAddr(), HashTableAddr() + hashtable_size);


    //initialize registers' labels to zero
  memset(registers_shadow,0,GLOBAL_POOL_SIZE*sizeof(dfsan_label));
}

//#if SANITIZER_CAN_USE_PREINIT_ARRAY
//__attribute__((section(".preinit_array"), used))
//static void (*dfsan_init_ptr)(int, char **, char **) = dfsan_init;
//#endif
