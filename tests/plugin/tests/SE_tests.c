//
// Created by sina on 2020-07-08.
//
// For testing, comment SANITIZER_CAN_USE_PREINIT_ARRAY in dfsan.h and compile with:
// gcc  -o dfsan_SE.o  ./tests/SE_tests.c `pkg-config --cflags glib-2.0` `pkg-config --libs glib-2.0` ./lib/SE/dfsan.o ./lib/SE/union_util.o ./lib/SE/union_hashtable.o ./lib/SE/taint_allocator.o
#define GLOBAL_POOL_SIZE 254

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <sys/file.h>
#include <sys/mman.h>

#include <glib.h>

#include "../lib/SE/dfsan_interface.h"

#include "../lib/SE/shadow_memory.h"
void *res;

#define dfsan_union(x,y,z,w) dfsan_union(x,y,z,w,0,0,UNASSIGNED,UNASSIGNED,0,UNASSIGNED)

int test_open(const char *name, uint64_t size, int *flags) {
    if (!name)
        return -1;
    char shmname[200];
    snprintf(shmname, sizeof(shmname), "/dev/shm/%d [%s]", getpid(), name);
    printf("name=%s\n",shmname);
    int fd = open(shmname, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRWXU);
    assert(fd>=0);
    int res = ftruncate(fd, size);
    assert(res==0);
    res = unlink(shmname);
    assert(res==0);
    return fd;
}

void test_mapping(){
    int flags = 0;
    int fd = test_open("shadow",0x2001ffff0000,&flags);
    printf("fd=%d\n",fd);
    void *res = mmap((void *)0x10000, 0x2001ffff0000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_NORESERVE | MAP_ANON, fd, 0);
    assert(res>0);
    printf("res at %p\n",res);
}

void /*__attribute__ ((constructor))*/ init()
{
    struct rlimit rlim;

    int r1 = getrlimit(RLIMIT_FSIZE, &rlim);
    if(rlim.rlim_max<=0xffffdffe00010000){ //it's the size used for unused memory
        rlim.rlim_max=0xffffffffffffffff;
        setrlimit(RLIMIT_FSIZE, &rlim);
    }
    //printf("rlimit=0x%lx\n",rlim.rlim_max);
}


void test_shadow_mem(){

    void *addr1 = (void *)0x807600;
    void *addr11 = (void *)0x807604;

    const dfsan_label *shd_a1 = dfsan_shadow_for(addr1);
    const dfsan_label *shd_a2 = dfsan_shadow_for(addr11);
    printf("shadow address for %p is %p\tshadow address for %p is %p\n",addr1,shd_a1,addr11,shd_a2);

    int sh_t = (uint64_t)shd_a2 - (uint64_t)(shd_a1);
    assert(sh_t==16);

    uint64_t test_offset = 0x600;

    void *app_base = (void *)0x700000040000;
    void *shd_base = (void *)0x000000008000;

    void *a_addr = (void *)((uint64_t)app_base + test_offset);
    void *s_addr = (void *)((uint64_t)shd_base + test_offset);

    const dfsan_label *test_offset_sh = dfsan_shadow_for((void *)test_offset);
    const dfsan_label *a_addr_sh = dfsan_shadow_for(a_addr);
    const dfsan_label *s_addr_sh = dfsan_shadow_for(s_addr);
    printf("Address/shadow pairs: %p=%p\t%p=%p\t%p=%p\n",(void *)test_offset,test_offset_sh,a_addr,a_addr_sh,s_addr,s_addr_sh);

}

void test_dfsan_simple(){
    uint32_t pos1 = 0x0001;

    dfsan_label l1=dfsan_create_label(pos1++);
    assert(l1>0);

    void *addr1 = (void *)0x700000847600;
    int sz = 4;

    dfsan_set_label(l1,addr1,sz);
    dfsan_label l2 = dfsan_read_label(addr1,sz); //should simply return the label (not union load)
    int l2_has_l1 = dfsan_has_label(l2, l1);
    printf("testing whether created label is equal to the set label for addr=%p\tl1=%d, l2=%d\n",addr1,l1, l2);
    assert(l2_has_l1);

    int l_cnt=dfsan_get_label_count();
    printf("testing whether number of labels is correct:\tlabel count=%d\n",l_cnt);
    assert(l_cnt==1);

    const dfsan_label_info *inf1 = dfsan_get_label_info(l2);
    printf("checking dfsan_get_label_info api op=%d, size=%d, op1=0x%llx, op2=0x%llx:\n",inf1->instruction.op,inf1->instruction.size,inf1->instruction.op1,inf1->instruction.op2);

    dfsan_label l3=dfsan_create_label(pos1);
    assert(l3>0);

    void *addr2 = (void *)0x807f00;

    dfsan_label l4 = dfsan_union(l1, l3, Add, 1);
    printf("checking whether l1=%d and l3=%d is part of l4=%d\n", l4, l1, l3);
    int c1 = dfsan_has_label(l4, l1);
    assert(c1);
    printf("checking registers shadow at %p len=%d is set to 0\n", registers_shadow, GLOBAL_POOL_SIZE);
    for (int i=0;i<GLOBAL_POOL_SIZE;i++){
        dfsan_label temp = dfsan_get_register_label(i);
        assert(temp==0);
    }
    int reg_id = 21;
    printf("checking reg_id=%d label set and get to label=%d\n",reg_id,l1);
    dfsan_set_register_label(reg_id, l1);
    dfsan_label t1 = dfsan_get_register_label(reg_id);
    assert(t1==l1);


    //load
    void *taint_start_addr = (void *)0x8075f0;
    for(int i=0;i<4;i++){
        dfsan_label lload=dfsan_create_label(pos1++);
        assert(lload>0);
        dfsan_set_label(lload,taint_start_addr+i,1);
    }

    dfsan_label taint_load = dfsan_read_label(taint_start_addr,4);
    const dfsan_label_info *inf2 = dfsan_get_label_info(taint_load);
    printf("checking dfsan_get_label_info api returned load=%d op=%d, size=%d, l1=%d, l2=%d, op1=0x%llx, op2=0x%llx:\n",Load,inf2->instruction.op,inf2->instruction.size,inf2->l1,inf2->l2,inf2->instruction.op1,inf2->instruction.op2);
    assert(inf2->instruction.op==Load);

    dfsan_label taint_concat_concrete = dfsan_read_label(taint_start_addr,8);
    const dfsan_label_info *inf3 = dfsan_get_label_info(taint_concat_concrete);
    printf("checking taint_load returned concat=%d op=%d, size=%d, l1=%d, l2=%d, op1=0x%llx, op2=0x%llx:\n",Concat,inf3->instruction.op,inf3->instruction.size,inf3->l1,inf3->l2,inf3->instruction.op1,inf3->instruction.op2);
    assert(inf3->instruction.op==Concat);

    void *taint_2nd_addr = (void *)0x8075ec;
    for(int i=0;i<4;i++){
        dfsan_label lload=dfsan_create_label(pos1++);
        assert(lload>0);
        dfsan_set_label(lload,taint_2nd_addr+i,1);
    }
    dfsan_label taint_concat_labels = dfsan_read_label(taint_2nd_addr,8);
    const dfsan_label_info *inf4 = dfsan_get_label_info(taint_concat_labels);
    printf("checking taint_load returned concat=%d with label=%d op=%d, size=%d, l1=%d, l2=%d, op1=0x%llx, op2=0x%llx:\n",Concat,taint_load,inf4->instruction.op,inf4->instruction.size,inf4->l1,inf4->l2,inf4->instruction.op1,inf4->instruction.op2);
    assert(inf4->instruction.op==Concat);
    assert(inf4->l2==taint_load);

    dfsan_label l5 = dfsan_union(taint_concat_concrete, taint_concat_labels, And, 8);
    void *taint_3nd_addr = (void *)0x8078d0;
    dfsan_set_label(l5,taint_3nd_addr,8);
    dfsan_label taint_trunc = dfsan_read_label(taint_3nd_addr+6,2);
    const dfsan_label_info *inf5 = dfsan_get_label_info(taint_trunc);
    printf("checking taint_load returned Truncate=%d with label=%d op=%d, size=%d, l1=%d, l2=%d, op1=0x%llx, op2=0x%llx:\n",Trunc,l5,inf5->instruction.op,inf5->instruction.size,inf5->l1,inf5->l2,inf5->instruction.op1,inf5->instruction.op2);
    assert(inf5->instruction.op==Trunc);
    assert(inf5->l1==l5);


    //store
    //testing store concat
    void *taint_store_addr = (void *)0x807526;
    dfsan_store_label(taint_concat_labels,taint_store_addr,8);
    int store_size_read = 4;
    dfsan_label taint_store_concat1 = dfsan_read_label(taint_store_addr,store_size_read);
    dfsan_label taint_store_concat2 = dfsan_read_label(taint_store_addr+4,store_size_read);

    const dfsan_label_info *inf6=dfsan_get_label_info(taint_concat_labels);
    printf("checking taint_store stored label=%d,l1=%d at address=0x%x, size=%d is=%d\n",taint_concat_labels,inf6->l1,taint_store_addr,store_size_read, taint_store_concat1);
    assert(taint_store_concat1==inf6->l1);
    printf("checking taint_store stored label=%d,l2=%d at address=0x%x, size=%d is=%d\n",taint_concat_labels,inf6->l2,taint_store_addr+4,store_size_read, taint_store_concat2);
    assert(taint_store_concat2==inf6->l2);

    //testing store Load
    void *taint_store_addr_load = (void *)0x607520;
    int store_load_size = 4;
    dfsan_store_label(taint_load,taint_store_addr_load,store_load_size);

    const dfsan_label_info *inf7=dfsan_get_label_info(taint_load);

    printf("checking taint_store load case, storing label=%d, op=%d at address=0x%x, size=%d starts at=%d\n",taint_load,inf7->instruction.op,taint_store_addr_load,store_load_size, inf7->l1);
    for(int i=0;i<store_load_size;i++){
        dfsan_label load_store_label=dfsan_read_label(taint_store_addr_load+i,1);
        assert(load_store_label==inf7->l1+i);
    }
    //testing store default
    void *taint_store_addr_def = (void *)0x7a7540;
    int store_def_size = 8;
    dfsan_store_label(l1,taint_store_addr_def,store_def_size);
    printf("checking taint_store default case, storing label=%d, at address=0x%x, size=%d\n",l1,taint_store_addr_def,store_def_size);
    for(int i=0;i<store_def_size;i++){
        dfsan_label load_store_label=dfsan_read_label(taint_store_addr_def+i,1);
        assert(load_store_label==l1);
    }

}

__attribute__((section(".preinit_array")))
static void (*dfsan_init_ptr)(void) = dfsan_init;

void mem_read(uint64_t vaddr, int len, void *buf)
{
    switch (vaddr){
        case 0x8075f4:
            ((char *)buf)[0]=0x0c;
            break;
        case 0x700000847600:
            ((char *)buf)[0]=0xd0;
            ((char *)buf)[1]=0xf1;
            ((char *)buf)[2]=0x0f;
            break;
        default:
            ((char *)buf)[0]=0x00;
            break;
    }
}

void reg_read(uint32_t reg, int len, void *buf)
{
    switch (reg){
        case 0x1:
            ((char *)buf)[0]=0x0d;
            break;
        case 0x2:
            ((char *)buf)[0]=0x01;
            ((char *)buf)[1]=0xff;
            break;
        case 0x3:
            ((char *)buf)[0]=0x01;
            ((char *)buf)[1]=0xff;
            ((char *)buf)[2]=0xc0;
            ((char *)buf)[1]=0x00;
            break;
        default:
            ((char *)buf)[0]=0x00;
            break;
    }
}

static const char *print_X86_instruction(dfsan_label_info *label){
    return (const char )"UNIMPLEMENTED";
}

static dfsan_settings settings = {.readFunc=&mem_read, .regValue=&reg_read, .printInst=&print_X86_instruction};

int main(){
    dfsan_init(&settings);
//    test_shadow_mem();
    test_dfsan_simple();
    return 0;
}