//
// Created by sina on 2020-09-18.
//

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

#include <errno.h>

#include <keystone/keystone.h>

#include "../lib/SE/asm_generation.h"


#define DEFAULT_CODE_GEN_BUFFER_SIZE (1 * (INT64_C(1) << 20)) //1Mb

void *code_gen_mmap;

int code_gen_index=0;

void (*concat_func)(long long unsigned int op1,short unsigned int op1_size,long long unsigned int op2,short unsigned int op2_size,short unsigned int concat_size,void *retaddr);

void (*trunc_func)(long long unsigned int op,short unsigned int orig_size,short unsigned int trunc_size,void *retaddr);

static void test_ks(unsigned char *encode, size_t *size, char *CODE){
    ks_engine *ks;
    ks_err err;
    size_t count; // num of statements as returned by keystone
    printf("Assembly construction:\n");
    err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
    if (err != KS_ERR_OK) {
        printf("ERROR: failed on ks_open()=%s quit\n", ks_strerror(ks_errno(ks)));
        assert(0);
    }
//    ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
    if (ks_asm(ks, CODE, 0, &encode, size, &count) != KS_ERR_OK) {
        printf("ERROR: ks_asm() failed & count = %lu, error = %s\n",
               count, ks_strerror(ks_errno(ks)));
    } else {
        printf("successfully assembled, size=%lu!,count=%lu %p\n",*size,count,encode);
        for (int i = 0; encode!=NULL && (i < *size); i++) {
            printf("%02x ", encode[i]);
            ((unsigned char *)code_gen_mmap)[code_gen_index++] = encode[i];
        }
        printf("\n");
    }
}


int main(){
    int fd = open("asm_map", O_RDWR|O_CREAT);
    if (fd == -1){
        printf("error openning file\n");
        exit(1);
    }
    size_t map_size = sysconf(_SC_PAGE_SIZE);
    ftruncate(fd,sysconf(_SC_PAGE_SIZE));
    code_gen_mmap = mmap(NULL,map_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
//    int pr_st=mprotect(code_gen_mmap, map_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    if(code_gen_mmap==((void *) -1)){
        printf("mmap error=%s\n",strerror(errno));
        close(fd);
        exit(1);
    }

    unsigned char *encode=NULL;
    size_t size = 0; //num of compiled bytes as  returned by keystone
    test_ks(encode, &size,CONCAT_HELPER_CODE);
    long long unsigned int new_op=0;
    long long unsigned int op1 = 0xf000bc;
    long long unsigned int op2 = 0xdb00;
    concat_func = code_gen_mmap;
    printf("Executing the assembled instructions for concat...\n");
    concat_func(0xf000bc,4,0xdb00,2,8,(void *)&new_op);
    printf("concating 4 bytes of 0x%llx with 2 bytes of 0x%llx => new_op=%llx\n",op1,op2,new_op);

    int trunc_index = code_gen_index;
    printf("current code_gen_index=%d\n",code_gen_index);
    encode = NULL;
    size = 0;
    test_ks(encode, &size,TRUNC_HELPER_CODE);
    trunc_func = (void *)&(((unsigned char *)code_gen_mmap)[trunc_index]);
    printf("Executing the assembled instructions for trunc...\n");
    new_op = 0;
    trunc_func(op1,4,2,(void *)&new_op);
    printf("truncating 4 bytes of 0x%llx to 2 bytes => new_op=%llx\n",op1,new_op);
    close(fd);
    return 0;
}