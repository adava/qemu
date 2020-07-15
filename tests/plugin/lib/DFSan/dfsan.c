//===-- dfsan.cpp ---------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
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
#include <sys/time.h>
#include <sys/resource.h>
#define kNumLabels  (1 << (sizeof(dfsan_label) * 8))

bool fast16labels = false;
typedef uint16_t atomic_dfsan_label;
static const dfsan_label kInitializingLabel = -1;
const char *dump_labels_at_exit = "dfsan_labels.txt";

static atomic_dfsan_label __dfsan_last_label;
static dfsan_label_info __dfsan_label_info[kNumLabels];

typedef atomic_dfsan_label dfsan_union_table_t[kNumLabels][kNumLabels];
// On Linux/x86_64, memory is laid out as follows:
//
// +--------------------+ 0x800000000000 (top of memory)
// | application memory |
// +--------------------+ 0x700000008000 (kAppAddr)
// |                    |
// |       unused       |
// |                    |
// +--------------------+ 0x200200000000 (kUnusedAddr)
// |    union table     |
// +--------------------+ 0x200000000000 (kUnionTableAddr)
// |   shadow memory    |
// +--------------------+ 0x000000010000 (kShadowAddr)
// | reserved by kernel |
// +--------------------+ 0x000000000000
//
// To derive a shadow memory address from an application memory address,
// bits 44-46 are cleared to bring the address into the range    //44-46 are fixed for all app addressed (representing 7 and then 8 is next addr)
// [0x000000008000,0x100000000000).  Then the address is shifted left by 1 to
// account for the double byte representation of shadow labels and move the //each shadow address would store a 16 bit ID, hence double byte representation
// address into the shadow memory range.  See the function shadow_for below.

// On Linux/MIPS64, memory is laid out as follows:
// +--------------------+ 0x10000000000 (top of memory)
// | application memory |
// +--------------------+ 0xF000008000 (kAppAddr)
// |                    |
// |       unused       |
// |                    |
// +--------------------+ 0x2200000000 (kUnusedAddr)
// |    union table     |
// +--------------------+ 0x2000000000 (kUnionTableAddr)
// |   shadow memory    |
// +--------------------+ 0x0000010000 (kShadowAddr)
// | reserved by kernel |
// +--------------------+ 0x0000000000

// On Linux/AArch64 (39-bit VMA), memory is laid out as follow:
//
// +--------------------+ 0x8000000000 (top of memory)
// | application memory |
// +--------------------+ 0x7000008000 (kAppAddr)
// |                    |
// |       unused       |
// |                    |
// +--------------------+ 0x1200000000 (kUnusedAddr)
// |    union table     |
// +--------------------+ 0x1000000000 (kUnionTableAddr)
// |   shadow memory    |
// +--------------------+ 0x0000010000 (kShadowAddr)
// | reserved by kernel |
// +--------------------+ 0x0000000000

// On Linux/AArch64 (42-bit VMA), memory is laid out as follow:
//
// +--------------------+ 0x40000000000 (top of memory)
// | application memory |
// +--------------------+ 0x3ff00008000 (kAppAddr)
// |                    |
// |       unused       |
// |                    |
// +--------------------+ 0x1200000000 (kUnusedAddr)
// |    union table     |
// +--------------------+ 0x8000000000 (kUnionTableAddr)
// |   shadow memory    |
// +--------------------+ 0x0000010000 (kShadowAddr)
// | reserved by kernel |
// +--------------------+ 0x0000000000

// On Linux/AArch64 (48-bit VMA), memory is laid out as follow:
//
// +--------------------+ 0x1000000000000 (top of memory)
// | application memory |
// +--------------------+ 0xffff00008000 (kAppAddr)
// |       unused       |
// +--------------------+ 0xaaaab0000000 (top of PIE address)
// | application PIE    |
// +--------------------+ 0xaaaaa0000000 (top of PIE address)
// |                    |
// |       unused       |
// |                    |
// +--------------------+ 0x1200000000 (kUnusedAddr)
// |    union table     |
// +--------------------+ 0x8000000000 (kUnionTableAddr)
// |   shadow memory    |
// +--------------------+ 0x0000010000 (kShadowAddr)
// | reserved by kernel |
// +--------------------+ 0x0000000000

static uint64_t UnusedAddr(void);
static atomic_dfsan_label *union_table(dfsan_label l1, dfsan_label l2);
static void dfsan_check_label(dfsan_label label);
dfsan_label __dfsan_union_load(dfsan_label *ls, uint64_t n);
void __dfsan_set_label(dfsan_label label, void *addr, uint64_t size);
dfsan_label __dfsan_union(dfsan_label l1, dfsan_label l2);



static inline dfsan_label *shadow_for(const void *ptr) { //sina: this new implementation might result in collision e.g. one address falling below the shadow memory area and one above.
    uint64_t index = ((((uint64_t) ptr) & ShadowMask()) << 1);
    return (dfsan_label *)(shadow_start + index);
}

void UnmapOrDie(void *addr, uint64_t size) {
    if (!addr || !size) return;
    uint64_t res = munmap(addr, size);
    if (res==-1) {
        printf("ERROR: failed to deallocate 0x%zx (%zd) bytes at address %p\n", size, size, addr);
        assert(0);
    }
}

int GetNamedMappingFd(const char *name, uint32_t size, int *flags) {
    if (!name)
        return -1;
    char shmname[200];
    snprintf(shmname, sizeof(shmname), "/dev/shm/%d [%s]", getpid(), name);
    int fd = open(shmname, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRWXU);
    assert(fd>=0);
    int res = ftruncate(fd, size);
//    printf("%s res=%d\n",shmname,res);
    internal_iserror(res,(char *)"ftruncate error");
    res = unlink(shmname);
    assert(res==0);
    return fd;
}

void *MmapNamed(void *addr, uint64_t length, int prot, int flags, const char *name) {
//    printf("mapping addr=0x%p, size=0x%lx\n",addr, length);
//    int fd = GetNamedMappingFd(name, length, &flags);
//    void *res = mmap(addr, length, prot, flags, fd, 0);
    void *res = mmap(NULL, length, prot, flags, -1, 0);

    if (res>0){
//        prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, addr, size, (uint64_t)name);
//        printf("mmap res=%p\n",res);
        return res;
    }
    else{
        printf("ERROR: failed to allocate 0x%zx (%zd) bytes at address %p \n", length, length, addr);
        assert(0);
    }
}

static bool MmapFixed(uint64_t fixed_addr, uint64_t size, int additional_flags, const char *name) {
    size = (size + 4096 - 1) & ~(4096 - 1);
    fixed_addr = fixed_addr & ~(4096 - 1);
    shadow_start = MmapNamed((void *)fixed_addr, size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE /*| MAP_FIXED */ | additional_flags | MAP_ANON, name); //sina: MAP_FIXED fails when not position dependent
    return true;
}

bool MmapFixedNoReserve(uint64_t fixed_addr, uint64_t size, const char *name) {
    return MmapFixed(fixed_addr, size, MAP_NORESERVE, name);
}

void *MmapFixedNoAccess(uint64_t fixed_addr, uint64_t size, const char *name) {
    return (void *)MmapNamed((void *)fixed_addr, size, PROT_NONE,
                             MAP_PRIVATE /*| MAP_FIXED */ | MAP_NORESERVE | MAP_ANON,
                             name);
}


static uint64_t UnusedAddr(void) {
  return MappingImpl(MAPPING_UNION_TABLE_ADDR) + sizeof(dfsan_union_table_t);
}

static atomic_dfsan_label *union_table(dfsan_label l1, dfsan_label l2) {
  return &(*(dfsan_union_table_t *) UnionTableAddr())[l1][l2];
}

// Checks we do not run out of labels.
static void dfsan_check_label(dfsan_label label) {
  if (label == kInitializingLabel) {
    printf("FATAL: DataFlowSanitizer: out of labels\n");
    assert(0);
  }
}

// Resolves the union of two unequal labels.  Nonequality is a precondition for
// this function (the instrumentation pass inlines the equality test).
dfsan_label __dfsan_union(dfsan_label l1, dfsan_label l2) {
  if (fast16labels)
    return l1 | l2;

  if (l1 == 0)
    return l2;
  if (l2 == 0)
    return l1;

  if (l1 > l2)
      Swap(dfsan_label,l1,l2);

  atomic_dfsan_label *table_ent = union_table(l1, l2);
  // we currently don't support threading
  dfsan_label label = 0;

    // Check whether l2 subsumes l1.  We don't need to check whether l1
    // subsumes l2 because we are guaranteed here that l1 < l2, and (at least
    // in the cases we are interested in) a label may only subsume labels
    // created earlier (i.e. with a lower numerical value).
    if (__dfsan_label_info[l2].l1 == l1 ||
        __dfsan_label_info[l2].l2 == l1) {
      label = l2;
    } else {
      label = ++__dfsan_last_label;
      dfsan_check_label(label);
      __dfsan_label_info[label].l1 = l1;
      __dfsan_label_info[label].l2 = l2;
    }
    *table_ent = label;

  return label;
}

dfsan_label __dfsan_union_load(dfsan_label *ls, uint64_t n) {
  dfsan_label label = ls[0];
  for (uint64_t i = 1; i != n; ++i) {
    dfsan_label next_label = ls[i];
    if (label != next_label)
      label = __dfsan_union(label, next_label);
  }
  return label;
}


// Like __dfsan_union, but for use from the client or custom functions.  Hence
// the equality comparison is done here before calling __dfsan_union.
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2) {
  if (l1 == l2)
    return l1;
  return __dfsan_union(l1, l2);
}

dfsan_label dfsan_create_label(const char *desc, void *userdata) {
  dfsan_label label = ++__dfsan_last_label;
  dfsan_check_label(label);
  __dfsan_label_info[label].l1 = __dfsan_label_info[label].l2 = 0;
  __dfsan_label_info[label].desc = desc;
  __dfsan_label_info[label].userdata = userdata;
  return label;
}

void __dfsan_set_label(dfsan_label label, void *addr, uint64_t size) {
  for (dfsan_label *labelp = shadow_for((const void *)addr); size != 0; --size, ++labelp) {
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

    *labelp = label;
  }
}

void dfsan_set_label(dfsan_label label, void *addr, uint64_t size) {
  __dfsan_set_label(label, addr, size);
}

void dfsan_add_label(dfsan_label label, void *addr, uint64_t size) {
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp)
    if (*labelp != label)
      *labelp = __dfsan_union(*labelp, label);
}

dfsan_label dfsan_read_label(const void *addr, uint64_t size) {
  if (size == 0)
    return 0;
  return __dfsan_union_load(shadow_for(addr), size);
}

const dfsan_label_info *dfsan_get_label_info(dfsan_label label) {
  return &__dfsan_label_info[label];
}

int dfsan_has_label(dfsan_label label, dfsan_label elem) {
  if (label == elem)
    return true;
  const dfsan_label_info *info = dfsan_get_label_info(label);
  if (info->l1 != 0) {
    return dfsan_has_label(info->l1, elem) || dfsan_has_label(info->l2, elem);
  } else {
    return false;
  }
}

dfsan_label dfsan_has_label_with_desc(dfsan_label label, const char *desc) {
  const dfsan_label_info *info = dfsan_get_label_info(label);
  if (info->l1 != 0) {
    return dfsan_has_label_with_desc(info->l1, desc) ||
           dfsan_has_label_with_desc(info->l2, desc);
  } else {
    return strcmp(desc, info->desc) == 0;
  }
}

size_t dfsan_get_label_count(void){
  return (size_t)__dfsan_last_label;
}

void dfsan_dump_labels(int fd) {
  dfsan_label last_label = __dfsan_last_label;

  for (uint32_t l = 1; l <= last_label; ++l){
    char buf[64];
    snprintf(buf, sizeof(buf), "%u %u %u ", l, __dfsan_label_info[l].l1, __dfsan_label_info[l].l2);
    write(fd, buf, strlen(buf));
    if (__dfsan_label_info[l].l1 == 0 && __dfsan_label_info[l].desc) {
      write(fd, __dfsan_label_info[l].desc, strlen(__dfsan_label_info[l].desc));
    }
    write(fd, "\n", 1);
  }
}

static void dfsan_fini(void) {
  if (strcmp(dump_labels_at_exit, "") != 0) {
    int fd = open(dump_labels_at_exit, O_WRONLY);
    if (fd == -1) {
      printf("WARNING: DataFlowSanitizer: unable to open output file %s\n", dump_labels_at_exit);
      return;
    }

    printf("INFO: DataFlowSanitizer: dumping labels to %s\n", dump_labels_at_exit);
    dfsan_dump_labels(fd);
    close(fd);
  }
}

void dfsan_flush(void) {
  UnmapOrDie((void*)ShadowAddr(), UnusedAddr() - ShadowAddr());
  if (!MmapFixedNoReserve(ShadowAddr(), UnusedAddr() - ShadowAddr(),"shadow"))
    assert(0);
}

// MmapFixedNoAccess call to ftruncate may violate the file size limit.  Change the limit via [rlim.rlim_max=0xffffffffffffffff; setrlimit(RLIMIT_FSIZE, &rlim);]
// Memory mapping fails if compiled without gcc -pie -fPIE options

static void dfsan_init(void){

//    struct rlimit rlim;
//    getrlimit(RLIMIT_FSIZE, &rlim);
//    if(rlim.rlim_max<=0xffffdffe00010000){ //it's the size used for unused memory
//        rlim.rlim_max=0xffffffffffffffff;
//        setrlimit(RLIMIT_FSIZE, &rlim);
//    }
//    printf("rlimit=0x%lx\n",rlim.rlim_max);

    kShadowSize = kUnionTableAddr - kShadowAddr;
    kUnionTableSize = sizeof(dfsan_union_table_t);
    kAllocationSize = kUnionTableSize + kShadowSize;

    if (!MmapFixedNoReserve(ShadowAddr(), kAllocationSize,"shadow")) //0x1ffff0000 is the largest size I could try with fixed_addr
            assert(0);
  // Protect the region of memory we don't use, to preserve the one-to-one
  // mapping from application to shadow memory. But if ASLR is disabled, Linux
  // will load our executable in the middle of our unused region. This mostly
  // works so long as the program doesn't use too much memory. We support this
  // case by disabling memory protection when ASLR is disabled.
  uint64_t init_addr = (uint64_t)&dfsan_init;
  if (!(init_addr >= UnusedAddr() && init_addr < AppAddr()))
    MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr(),"unused");
  __dfsan_label_info[kInitializingLabel].desc = "<init label>";

  //initialize registers' labels to zero
  memset(registers_shadow,0,GLOBAL_POOL_SIZE*sizeof(dfsan_label));

}
