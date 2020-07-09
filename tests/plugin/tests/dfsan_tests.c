//
// Created by sina on 2020-07-08.
//
// For testing compile with -pie -fPIE options; gcc -pie -fPIE -o tests/dfsan_tests.o tests/dfsan_tests.c; ./s/dfsan_tests.o

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
}

__attribute__((section(".init_array")))
static void (*dfsan_init_ptr)(void) = init;

int main(){
    dfsan_init();
    test_dfsan_simple();
    return 0;
}