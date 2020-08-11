#include "./sanitizer_common/sanitizer_atomic.h"
#include "./sanitizer_common/sanitizer_common.h"
#include "dfsan.h"
#include "taint_allocator.h"

using namespace __sanitizer;
static const uptr hashtable_size = (1ULL << 32);
namespace __taint {

static uptr begin_addr;
static atomic_uint64_t next_usable_byte;
static uptr end_addr;
/**
 * Initialize allocator memory,
 * begin: first usable byte
 * end: first unusable byte
 */

void allocator_init(uptr begin, uptr end) {
  begin_addr = begin;
  atomic_store_relaxed(&next_usable_byte, begin);
  end_addr = end;
}

#ifndef SANITIZER_CAN_USE_PREINIT_ARRAY
void init_mem() {
    __dfsan::kShadowSize = MappingArchImpl<MAPPING_UNION_TABLE_ADDR>() - MappingArchImpl<MAPPING_SHADOW_ADDR>();
    __dfsan::kUnionTableSize = MappingArchImpl<MAPPING_HASH_TABLE_ADDR>() - MappingArchImpl<MAPPING_UNION_TABLE_ADDR>();
    __dfsan::kAllocationSize = kUnionTableSize + kShadowSize + hashtable_size;

    if (!MmapFixedNoReserve(ShadowAddr(), kAllocationSize, &shadow_start)) //0x1ffff0000 is the largest size I could try with fixed_addr
        assert(0);

    allocator_init(__dfsan::HashTableAddr(), __dfsan::HashTableAddr() + hashtable_size);
}
#endif

void *allocator_alloc(uptr size) {
  if (begin_addr == 0) {
#ifndef SANITIZER_CAN_USE_PREINIT_ARRAY
      init_mem();
#else
      printf("FATAL: Allocator not initialized, begin_addr=%lx\n",begin_addr);
      Die();
#endif
  }
  uptr retval = atomic_fetch_add(&next_usable_byte, size, memory_order_relaxed);
  if (retval + size >= end_addr) {
    printf("FATAL: Allocate size exceeded\n");
    Die();
  }
  return reinterpret_cast<void *>(retval);
}

void
allocator_dealloc(uptr addr) {
  // do nothing for now
}

} // namespace
