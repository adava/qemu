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

//#include "../../lib/utility.c"

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
const char *graphviz_file = "union_graphviz.gv";

static atomic_dfsan_label __dfsan_last_label;
static dfsan_label_info *__dfsan_label_info;
//static guest_memory_read_func read_guest;

static const char*(*print_inst)(dfsan_label_info *label);

static dfsan_settings *settings;

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
    } else if ((uptr) (&__dfsan_label_info[label]) >= HashTableAddr()) {
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
    const u32 PRIME32_4 = 668265263U;
    const u32 PRIME32_5 = 374761393U;

#define XXH_rotl32(x, r) ((x << r) | (x >> (32 - r)))
    u32 h32 = PRIME32_5;
    h32 += h1 * PRIME32_3;
    h32 = XXH_rotl32(h32, 17) * PRIME32_4;
    h32 += h2 * PRIME32_3;
    h32 = XXH_rotl32(h32, 17) * PRIME32_4;
    h32 += h3 * PRIME32_3;
    h32 = XXH_rotl32(h32, 17) * PRIME32_4;
#undef XXH_rotl32

    h32 ^= h32 >> 15;
    h32 *= PRIME32_2;
    h32 ^= h32 >> 13;
    h32 *= PRIME32_3;
    h32 ^= h32 >> 16;

    return h32;
}

static inline dfsan_label_info *get_label_info(dfsan_label label) {
    return &__dfsan_label_info[label];
}

static inline bool is_constant_label(dfsan_label label) {
    return label == CONST_LABEL;
}

static inline bool is_kind_of_label(dfsan_label label, u16 kind) {
    return get_label_info(label)->instruction.op == kind;
}

static bool isZeroOrPowerOfTwo(uint16_t x) { return (x & (x - 1)) == 0; }

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
const dfsan_label *dfsan_shadow_for(const void *addr) {
    return shadow_for(addr);
}


inline dfsan_label concrete_label(u64 operand, enum shadow_type operand_type, u16 size){
    u64 operand_value = 0;
    dfsan_label label = 0;
    if(operand_type==MEMORY || operand_type==MEMORY_IMPLICIT){
        settings->readFunc(operand,size,&operand_value);
    }
    else if(operand_type==GLOBAL || operand_type==GLOBAL_IMPLICIT){
        settings->regValue(operand,size,&operand_value);
    }
    else{
        AOUT("shouldn't use concrete_label for this operand typ=%d\n",operand_type);
        assert(0);
    }

    struct dfsan_label_info label_info = {
            .l1 = CONST_LABEL, .l2 = CONST_LABEL, .instruction={.op1 = operand_value, .op1_type=IMMEDIATE, .op2 = 0, .op2_type = UNASSIGNED, .dest = 0, .dest_type = UNASSIGNED, .op = Load_REG, .size = size},
            .flags = 0, .tree_size = 0, .hash = 0 /*, .expr = nullptr, .deps = nullptr */}; //we don't assign op2 and dest to avoid many duplicate IMM values in the union table
    __taint::option res = __union_table.lookup(label_info);
    if (res != __taint::none()) {
        label = *res;
        return label;
    }
    label = atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
    dfsan_check_label(label);
    memcpy(&__dfsan_label_info[label], &label_info, sizeof(dfsan_label_info));

    return label;

}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_union(dfsan_label l1, dfsan_label l2, u16 op, u16 size,
                          u64 op1, u64 op2, enum shadow_type op1_type, enum shadow_type op2_type, u64 dest,
                          enum shadow_type dest_type) {
//  if (l1 > l2 && is_commutative(op)) { //sina: not sure whether this should be kept; in the binary generation, we might run to some problems. Swapping also the dest might work but not sure what the implications will be in this stage!
//    // needs to swap both labels and concretes
//    Swap(l1, l2);
//    Swap(op1, op2);
//  }
    if (l1 == 0 && l2 < CONST_OFFSET  && op!=UNION_MULTIPLE_OPS/*&& op != fsize*/) return 0; //sina: no fsize at the moment
    if (l2 == 0 && l1 < CONST_OFFSET  && op!=UNION_MULTIPLE_OPS/*&& op != fsize*/) return 0; //because we do not swap

    if (l1 == kInitializingLabel || l2 == kInitializingLabel) return kInitializingLabel;

//  if (l1 >= CONST_OFFSET) op1 = 0;
//  if (l2 >= CONST_OFFSET) op2 = 0;

    if(IS_MEMORY(op1_type)){
        op1 = 0; //memory addr will be decided later
    }
    if(IS_MEMORY(op2_type)){
        op2 = 0;
    }
    if(IS_MEMORY(dest_type)){
        dest = 0;
    }

    if(l1==CONST_LABEL && ((int)op1_type>=(int)GLOBAL && (int)op1_type<=(int)MEMORY_IMPLICIT)){
        l1 = concrete_label(op1,op1_type,size);
    }
    if(l2==CONST_LABEL && ((int)op2_type>=(int)GLOBAL && (int)op2_type<=(int)MEMORY_IMPLICIT)){
        l2 = concrete_label(op2,op2_type,size);
    }
    struct dfsan_label_info label_info = {
            .l1 = l1, .l2 = l2, .instruction={.op1 = op1, .op1_type=op1_type, .op2 = op2, .op2_type = op2_type, .dest = dest, .dest_type = dest_type, .op = op, .size = size},
            .flags = 0, .tree_size = 0, .hash = 0 /*, .expr = nullptr, .deps = nullptr */};

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

inline const dfsan_label merge_labels(const dfsan_label *ls,int first, int last,const void *addr){
    dfsan_label ret;
    dfsan_label label0 = ls[first];
    int load_size = last - first + 1;
    if(is_constant_label(label0)){ //since the constants are going to be concatenated with taint in the caller we need to read the concretes
        assert(load_size<SHD_SIZE_MAX);
        ret = concrete_label((u64)addr,MEMORY,load_size);
    }
    else if(load_size==1){ //no need to union
        ret = label0;
    }
    else if(get_label_info(label0)->instruction.op==TAINT){ //a bunch of consecutve tainted bytes
        ret = __taint_union(label0, CONST_LABEL, Load, load_size, 0, 0, UNASSIGNED, UNASSIGNED, 0, //sina: load_size as l2 doesn't make sense; at least for binary propagation
                            UNASSIGNED);
    }
    else{
        if(load_size!=get_label_info(label0)->instruction.size){ //Truncate, might need to change the condition to <=
            ret = __taint_union(label0, CONST_LABEL, Trunc, load_size, get_label_info(label0)->instruction.dest, 0, MEMORY,
                                              UNASSIGNED, 0, UNASSIGNED); //recording the start offset and size to exactly locate the target bytes; assumes the memory offsets are stored in dest
        }
        else{
            ret = label0; //we are reading a perfectly aligned label
        }
    }
    return ret;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __taint_union_load(const void *addr, const dfsan_label *ls, uptr n) {
    int last=0;
    dfsan_label ret = ls[last];

    if (ret == kInitializingLabel) return kInitializingLabel; //kInitializingLabel is the max, if we reach that value, we ran out of labels

    if (ret >= CONST_OFFSET) assert(get_label_info(ret)->instruction.size != 0);

    for (int i=1; i<n;i++){ //can't just compare label size and return, the following bytes might have been overwritten
        if(ls[last]!=ls[i]){
            if (ls[i] == kInitializingLabel) return kInitializingLabel;

            if (!(get_label_info(ls[last])->instruction.op==TAINT && get_label_info(ls[i])->instruction.op==TAINT && get_label_info(ls[last])->instruction.op1+(i-last)==get_label_info(ls[i])->instruction.op1)){ //check whether they are consecutive raw input bytes
                dfsan_label temp = merge_labels(ls,last,i-1,addr);
                if(last==0){
                    ret = temp;
                }
                else{
                    ret = __taint_union(ret, temp, Concat, i + 1, 0, 0, UNASSIGNED, UNASSIGNED, 0, UNASSIGNED);
                }
                last = i;
            }
            //else continue
        }
        //else continue
    }
    if(last!=0){ //the last chunk is not unified
        dfsan_label temp = merge_labels(ls,last,n-1,addr);
        ret = __taint_union(ret, temp, Concat, n, 0, 0, UNASSIGNED, UNASSIGNED, 0, UNASSIGNED);
    }
    else if(get_label_info(ret)->instruction.op==TAINT && n==get_label_info(ls[n-1])->instruction.op1-get_label_info(ret)->instruction.op1+1){ //aligned Load case
        ret = merge_labels(ls,last,n-1,addr);
    }
    else if(!is_constant_label(ret) && n<get_label_info(ret)->instruction.size){ //aligned Truncate case
        ret = merge_labels(ls,last,n-1,addr);
    }
    //else all the labels are the same (could be CONST_LABEL)
    return ret;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __taint_union_store(dfsan_label l, dfsan_label *ls, uptr n) {
    AOUT("store label = %d, n = %d, ls = %p\n", l, n, ls);
    if (l != kInitializingLabel) {
        // for debugging
        dfsan_label h = atomic_load(&__dfsan_last_label, memory_order_relaxed);
        assert(l <= h);
    } else {
        return;
    }
    // check how the source label is created
    switch (__dfsan_label_info[l].instruction.op) {
        case Load: {
            // if source label is union load, just break it up
            dfsan_label label0 = __dfsan_label_info[l].l1;
            uptr s = n < __dfsan_label_info[l].instruction.size ? n : __dfsan_label_info[l].instruction.size;
            for (uptr i = 0; i < s; ++i)
                ls[i] = label0 + i;
            break;
        }
        case Concat: {
            u16 label_size = __dfsan_label_info[l].instruction.size;
            dfsan_label left = __dfsan_label_info[l].l1;
            u16 left_size = __dfsan_label_info[left].instruction.size;
            if(n==label_size){
                dfsan_label right = __dfsan_label_info[l].l2;
                __taint_union_store(left, ls, left_size);
                __taint_union_store(right, &ls[left_size], n-left_size);
                break;
            }
            else if(n<=left_size){
                dfsan_label ret = __taint_union(left, CONST_LABEL, Trunc, n, get_label_info(left)->instruction.dest, 0, MEMORY,
                                                UNASSIGNED, 0, UNASSIGNED);
                l = ret;
            }
            else if(n>left_size && n<label_size){
                __taint_union_store(left, ls, left_size);
                dfsan_label right = __dfsan_label_info[l].l2;
                dfsan_label ret = __taint_union(right, CONST_LABEL, Trunc, n-left_size, get_label_info(right)->instruction.dest, 0, MEMORY,
                                                UNASSIGNED, 0, UNASSIGNED);
                l = ret;
            }
        }
        //we don't have zExt and Extracts
        default: {
            for (uptr i = 0; i < n; ++i)
                ls[i] = l;
            break;
        }
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
dfsan_label
dfsan_union(dfsan_label l1, dfsan_label l2, u16 op, u8 size, u64 op1, u64 op2, u8 op1_type, u8 op2_type, u64 dest,
            u8 dest_type) {
    return __taint_union(l1, l2, op, size, op1, op2, (enum shadow_type) op1_type, (enum shadow_type) op2_type, dest,
                         (enum shadow_type) dest_type);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label dfsan_create_label(off_t offset) {
    dfsan_label label =
            atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed) + 1;
    dfsan_check_label(label);
    memset(&__dfsan_label_info[label], 0, sizeof(dfsan_label_info));
    __dfsan_label_info[label].instruction.size = 1;
    // label may not equal to offset when using stdin
    __dfsan_label_info[label].instruction.op1 = offset;
    __dfsan_label_info[label].instruction.op = TAINT; //with the old Kirenenko load/store, this causes problem since there op==0 is expectec
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
        *labelp = __taint_union(*labelp, label, op, 1, 0, 0, UNASSIGNED, UNASSIGNED, 0, UNASSIGNED);
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
    return __taint_union_load(addr, shadow_for(addr), size);
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_get_label(const void *addr) {
    return *shadow_for(addr);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
struct dfsan_label_info *dfsan_get_label_info(dfsan_label label) {
    return &__dfsan_label_info[label];
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int
dfsan_has_label(dfsan_label label,
                dfsan_label elem) { //sina: this is different than DFSan, here elem in l2 is part of label only if l1 is zero
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

shadow_err check_registers(uint64_t start, uint64_t end) {
    assert(start <= end);
    assert(start < GLOBAL_POOL_SIZE);

    for (uint64_t i = start; i <= end; i++) {
        dfsan_label label = registers_shadow[i];
        if (label != 0) {
            return 2;
        }
    }
    return 0;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
mark_input_bytes(void *addr, int64_t ret, uint8_t invok) { //invok is not currently used but it should be useful for interactive apps
//    char *desc = malloc(20);
//    sprintf(desc,"%d",value);
    for (int i = 0; i < ret; i++) {
        dfsan_label label = dfsan_create_label(invok+i);
        dfsan_set_label(label, addr + i, 1);
    }
//    printf("exiting mark_input\n");
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
dfsan_dump_labels(int fd) {
    dfsan_label last_label =
            atomic_load(&__dfsan_last_label, memory_order_relaxed);
    char *title = "label, l1, l2, op, size, op1, type, op2, type, dst, type\n";
    write(fd, title, strlen(title));
    for (uptr l = 1; l <= last_label; ++l) {
        char buf[128];
        snprintf(buf, sizeof(buf), "%u = (%u, %u, %u, %u, %llu, %d, %llu, %d, %llu, %d)\n",
                 l, __dfsan_label_info[l].l1, __dfsan_label_info[l].l2, __dfsan_label_info[l].instruction.op,
                 __dfsan_label_info[l].instruction.size, __dfsan_label_info[l].instruction.op1, __dfsan_label_info[l].instruction.op1_type,
                 __dfsan_label_info[l].instruction.op2, __dfsan_label_info[l].instruction.op2_type, __dfsan_label_info[l].instruction.dest,
                 __dfsan_label_info[l].instruction.dest_type);
        for (int i = 0; buf[i] != '\n'; i++) {
            write(fd, &buf[i], 1);
        }
        write(fd, "\n", 1);
    }
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int dfsan_fini(char *lfile, char *graph_file) {
    if (lfile==NULL || strcmp(lfile, "") == 0) {
        lfile = (char *)dump_labels_at_exit;
    }
    if (graph_file==NULL || strcmp(graph_file, "") == 0) {
        graph_file = (char *)graphviz_file;
    }
    int fd = open(lfile, O_RDWR | O_CREAT | O_TRUNC, 0777);
    if (fd == -1) {
        printf("WARNING: DataFlowSanitizer: unable to open output file %s\n", lfile);
        printf("file open error=%s\n",strerror(errno));
        assert(0);
    }
    printf("INFO: DataFlowSanitizer: dumping labels to %s\n", lfile);
    dfsan_dump_labels(fd);
    //dump_shadows();
    close(fd);

    dfsan_label root = atomic_load(&__dfsan_last_label, memory_order_relaxed);

    // write output
    char *afl_shmid = getenv("__AFL_SHM_ID");
    if (afl_shmid) {
        u32 shm_id = atoi(afl_shmid);
        void *trace_id = shmat(shm_id, NULL, 0);
        *(reinterpret_cast<u32 *>(trace_id)) = ++__current_index;
        shmdt(trace_id);
    }
    return (int)root;
}

#if SANITIZER_CAN_USE_PREINIT_ARRAY
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void dfsan_init(dfsan_settings *sets) {

    __dfsan::kShadowSize = MappingArchImpl<MAPPING_UNION_TABLE_ADDR>() - MappingArchImpl<MAPPING_SHADOW_ADDR>();
    __dfsan::kUnionTableSize = MappingArchImpl<MAPPING_HASH_TABLE_ADDR>() - MappingArchImpl<MAPPING_UNION_TABLE_ADDR>();
    __dfsan::kAllocationSize = kUnionTableSize + kShadowSize + hashtable_size;

//    printf("kShadowSize=%lx\tkUnionTableSize=%lx\tkAllocationSize=%lx\n",kShadowSize,kUnionTableSize,kAllocationSize);

    if (!MmapFixedNoReserve(ShadowAddr(), kAllocationSize, &shadow_start)) //0x1ffff0000 is the largest size I could try with fixed_addr
        assert(0);

//    printf("MmapFixedNoReserve 1 finished, shadow_start=%lx\n",shadow_start);

    __dfsan_label_info = (dfsan_label_info *)UnionTableAddr();

    // init const size
  __dfsan_label_info[CONST_LABEL].instruction.size = 1;

//    MmapFixedNoReserve(HashTableAddr(), hashtable_size); //sina: not sure about this

//    printf("UnionTableAddr=%lx\n",UnionTableAddr());
//    printf("HashTableAddr=%lx\n",HashTableAddr());


    __taint::allocator_init(HashTableAddr(), HashTableAddr() + hashtable_size);


    //initialize registers' labels to zero
  memset(registers_shadow,0,GLOBAL_POOL_SIZE*sizeof(dfsan_label));

  SHD_init();

  settings = sets;
}

//__attribute__((section(".preinit_array"), used))
//static void (*dfsan_init_ptr)(dfsan_settings *) = dfsan_init;

#else
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void dfsan_init(dfsan_settings *funcs) {

//  the memory initialization will be done in taint alloc (because of constructors execution order)
    SHD_init();
    __dfsan_label_info = (dfsan_label_info *) UnionTableAddr();

    // init const size
    __dfsan_label_info[CONST_LABEL].instruction.size = 1;

    memset(registers_shadow, 0, GLOBAL_POOL_SIZE * sizeof(dfsan_label));

    settings = funcs;
}
#endif
