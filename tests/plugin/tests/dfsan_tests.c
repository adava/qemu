//
// Created by sina on 2020-07-08.
//
// For testing compile with -pie -fPIE options; gcc -pie -fPIE -o tests/dfsan_tests.o tests/dfsan_tests.c; ./s/dfsan_tests.o

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

#include "../lib/DFSan/dfsan_interface.h"
#include "../lib/DFSan/dfsan.h"
#include "../lib/DFSan/dfsan.c"
void *res;

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

void test_dfsan_simple(){
    char *tdesc = "test description";
    uint32_t userdata = 0x0001;

    dfsan_label l1=dfsan_create_label(tdesc, &userdata);
    assert(l1>0);

    void *addr1 = (void *)0x807600;
    int sz = 4;

    dfsan_set_label(l1,addr1,sz);
    dfsan_label l2 = dfsan_read_label(addr1,sz);
    printf("testing whether created label is equal to the set label for addr=%p\tl1=%d, l2=%d\n",addr1,l1, l2);
    assert(l1==l2);

    int l_cnt=dfsan_get_label_count();
    printf("testing whether number of labels is correct:\tlabel count=%d\n",l_cnt);
    assert(l_cnt==1);

    const dfsan_label_info *inf1 = dfsan_get_label_info(l2);
    printf("checking dfsan_get_label_info api:\tdfsan_label_info.tdesc=%s\n",inf1->desc);

    dfsan_label l3=dfsan_create_label(tdesc, &userdata);
    assert(l3>0);

    void *addr2 = (void *)0x807f00;

    dfsan_label l4 = dfsan_union(l1, l3);
    printf("checking whether l1=%d and l3=%d is part of l4=%d\n", l4, l1, l3);
    int c1 = dfsan_has_label(l4, l1);
    assert(c1);
    int c2 = dfsan_has_label(l4, l3);
    assert(c2);
    printf("checking registers shadow at %p len=%d is set to 0\n", registers_shadow, GLOBAL_POOL_SIZE);
    for (int i=0;i<GLOBAL_POOL_SIZE;i++){
        assert(registers_shadow[i]==0);
    }
    int reg_id = 21;
    printf("checking reg_id=%d label set and get to label=%d\n",reg_id,l1);
    dfsan_set_register_label(reg_id, l1);
    dfsan_label t1 = dfsan_get_register_label(reg_id);
    assert(t1==l1);
}

__attribute__((section(".init_array")))
static void (*dfsan_init_ptr)(void) = init;

int main(){
    dfsan_init();
    test_dfsan_simple();
    return 0;
}