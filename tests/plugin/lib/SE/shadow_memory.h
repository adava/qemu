#ifndef SHADOW_MEMORY_H
#define SHADOW_MEMORY_H


#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#ifdef DEBUG_ON
#define DEBUG_TAINT_SOURCE(inq, value)     if (value!=0){\
                                                    printf("inquiry is tainted => inq.type=%d, addr/id=0x%lx, size=%d\n",inq->type,inq->addr.vaddr,inq->size);\
                                                    assert(0);}
#else
#define DEBUG_TAINT_SOURCE(inq, value)
#endif


#define MAX_NUM_FLAGS 64
#define TARGET_PAGE_BITS 12

#define DEREF_TYPE(buf,type) (*(type*)buf)


#define PAGE_SIZE_BITS TARGET_PAGE_BITS
#define NUM_PAGES_BITS (32 - PAGE_SIZE_BITS)
#define PAGE_SIZE (1 << PAGE_SIZE_BITS)
#define OFFSET_MASK  (PAGE_SIZE - 1)
#define PAGE_MASK  ((1 << NUM_PAGES_BITS) - 1)
#define SHD_find_offset(vaddr) ((uint32_t)(vaddr & OFFSET_MASK)) // no need to shift left by 2 to account for the dfsan_label 4 bytes size, we use the offset as array index
#define SHD_PAGE_INDEX(vaddr) (vaddr >> PAGE_SIZE_BITS)
#define SHD_find_page_addr(vaddr) (vaddr & PAGE_MASK)
#define SHD_KEY_CONVERSION(addr) ((gconstpointer)SHD_PAGE_INDEX(vaddr))
#define SHD_assemble_addr(page, addr) (page << PAGE_SIZE_BITS | addr)

#ifndef GLOBAL_POOL_SIZE
#ifdef X86_REG_ENDING
#define GLOBAL_POOL_SIZE X86_REG_ENDING + 20 //Capstone has 234 X86 registers, we allocate a few more for temps
#else
#define GLOBAL_POOL_SIZE 254
#endif
#endif

#include "defs.h"

#define copy_inq(src, dst)  dst.addr.vaddr = src.addr.vaddr;\
                            dst.type = src.type;\
                            dst.size = src.size;
typedef struct shadow_page_struct {
    dfsan_label bitmap[PAGE_SIZE]; /* Contains the bitwise tainting data for the page */
} shadow_page;

/* Middle node for holding memory taint information */
typedef struct shadow_memory_struct {
    GHashTable *pages; //it’s a hashmap of shadow_pages
} shadow_memory;

enum shadow_type{
    TEMP = 1, //so we can distinguish uninitialized inquiries
    GLOBAL,
    MEMORY,
    IMMEDIATE, //used for SHIFT, this type MUST not be passed to the shadow storage
    FLAG
};

typedef enum {
    SHD_SIZE_u8= sizeof(uint8_t),
    SHD_SIZE_u16= sizeof(uint16_t),
    SHD_SIZE_u32= sizeof(uint32_t),
    SHD_SIZE_u64= sizeof(uint64_t),
    SHD_SIZE_MAX
} SHD_SIZE;

typedef struct inquiry{
    union{
        uint64_t vaddr;
        int id;
    }addr;
    enum shadow_type type;
    uint8_t size;
} shad_inq;

typedef int shadow_err;

typedef uint64_t SHD_value;

shadow_memory SHD_Memory;

void SHD_init(void);


guint SHD_ghash_addr(gconstpointer key);

shadow_page *find_shadow_page(uint64_t vaddr); // would get the higher part of the address and searches SHD_Memory pages for the inquiry page

void *get_shadow_memory(uint64_t vaddr); //the entire memory is addressable, plus this is an internal function. The caller fetches properly


guint SHD_ghash_addr(gconstpointer key){
    uint64_t h = (uint64_t)key;
    h = SHD_find_page_addr(h);
//  printf("in SHD_ghash_addr, key=%llx, h=%llx\n",(uint64_t)key,h);
    return ((guint)h);
}


void SHD_init(void){
    SHD_Memory.pages = g_hash_table_new_full(SHD_ghash_addr, g_direct_equal, NULL, NULL);
}

shadow_page *find_shadow_page(uint64_t vaddr){
    shadow_page *page = (shadow_page *)g_hash_table_lookup (SHD_Memory.pages,SHD_KEY_CONVERSION(vaddr));
    return page;
}


void *get_shadow_memory(uint64_t vaddr){
    shadow_page *page = find_shadow_page(vaddr);
    if (page==NULL){
        page = g_new0(shadow_page,1);
        g_hash_table_insert(SHD_Memory.pages,(gpointer)(SHD_KEY_CONVERSION(vaddr)),page);
    }
    return &page->bitmap[SHD_find_offset(vaddr)];
}


#endif