//
// Created by sina on 2020-09-18.
//

/* For testing, follow these steps:
 * Install Keystone
 * gcc  -o bin_testing.o bin_testing.c -lkeystone -lstdc++ -lm
*/

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

#include <sys/stat.h>

#include <keystone/keystone.h>

#include "../lib/SE/asm_generation.h"

#include "../lib/SE/bin_gen.c"

#define DEFAULT_CODE_GEN_BUFFER_SIZE (1 * (INT64_C(1) << 20)) //1Mb

char slice_inputs[32]={'\0'};

void test_helper_calls(){
    unsigned char *encode=NULL;
    size_t size = 0; //num of compiled bytes as  returned by keystone
    printf("CONCAT_HELPER:\n");
    printf("%s",CONCAT_HELPER_CODE);
    concat_func = assemble_and_write(encode, &size,CONCAT_HELPER_CODE);
    long long unsigned int new_op=0;
    long long unsigned int op1 = 0xf000bc;
    long long unsigned int op2 = 0xdb00;
    printf("Executing the assembled instructions for concat...\n");
    concat_func(0xf000bc,4,0xdb00,2,8,(void *)&new_op);
    printf("concating 4 bytes of 0x%llx with 2 bytes of 0x%llx => new_op=%llx\n",op1,op2,new_op);
    assert(new_op==0xdb0000f000bc);
    int trunc_index = code_gen_index;
    printf("current code_gen_index=%d\n",code_gen_index);
    encode = NULL;
    size = 0;
    printf("TRUNC_HELPER:\n");
    printf("%s",TRUNC_HELPER_CODE);
    assemble_and_write(encode, &size,TRUNC_HELPER_CODE);
    trunc_func = (void *)&(((unsigned char *)code_gen_mmap)[trunc_index]);
    printf("Executing the assembled instructions for trunc...\n");
    new_op = 0;
    trunc_func(op1,4,2,(void *)&new_op);
    printf("truncating 4 bytes of 0x%llx to 2 bytes => new_op=%llx\n",op1,new_op);
    assert(new_op==0xbc);
}

void test_sample_slice(char *asm_file, unsigned long int expected_value){
    long long unsigned int ret = 0;
    int st_size=0;
    size_t assembled_bytes_size=0;
    char *asm_gen_code;
    slice_func exec_addr = executable_from_asm(asm_file,&asm_gen_code,&st_size,&assembled_bytes_size);

    printf("assembly code:\n");
    for (int i=0;i<st_size;i++){
        printf("%c",asm_gen_code[i]);
    }
    printf("\n");

    if(assembled_bytes_size>0){
        printf("Executing the assembled instructions for the sample slice, expected value=%lu...\n",expected_value);

        char input[8]={'K','\0','4','\0','\0','\0','\0','\0'}; //since we set 8 for init_asm_generation, and my system allocates 2 bytes per input char
        ret = exec_addr(input,8);
        printf("ret=%llx\n",ret);
        assert(ret==expected_value); //for sample_generated_asm.asm, the ret should be zero

    }
    else{
        printf("ERROR in assembling, no bytes were assembled\n");
    }
}

void main(int argc, char *argv[]){
    int fd=initialize_executable_file(SLICE_EXEC_FILE);
    test_helper_calls();
    if(argc>2){
        test_sample_slice(argv[1],atoi(argv[2]));
    }
    else{
        test_sample_slice("sample_generated_asm.asm",0);
    }
    close(fd);
}