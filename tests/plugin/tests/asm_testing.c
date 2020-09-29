//
// Created by sina on 2020-09-18.
//

/* For testing, follow these steps:
 * Install Keystone
 * gcc  -o asm_testing.o asm_testing.c -lkeystone -lstdc++ -lm
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

#define CONCAT_HELPER_NAME "concat_func"
#define TRUNC_HELPER_NAME "truncate_func"
#define CONCAT_HELPER_CODE "push    rbp;mov     rbp, rsp;mov     [rbp-18h], rdi;mov     [rbp-28h], rdx;mov     eax, ecx;\
                            mov     edx, r8d;mov     [rbp-38h], r9;mov     [rbp-1ch], si;mov     [rbp-20h], ax;mov     [rbp-2ch], dx;\
                            movzx   eax, word ptr [rbp-1ch];shl     eax, 3;mov     rdx, [rbp-28h];mov     ecx, eax;shl     rdx, cl;\
                            mov     rax, rdx;mov     [rbp-10h], rax;mov     rax, [rbp-18h];or      rax, [rbp-10h];mov     [rbp-8], rax;\
                            movzx   eax, word ptr [rbp-2ch];cmp     eax, 2;jz loc_size_2;cmp     eax, 2;jg loc_size_cmp;\
                            cmp     eax, 1;jz loc_size_1;jmp loc_4006E3;loc_size_cmp:cmp     eax, 4;jz loc_size_4;\
                            cmp     eax, 8;jz loc_size_8;jmp loc_4006E3;loc_size_1:mov     rax, [rbp-8];\
                            mov     edx, eax;mov     rax, [rbp-38h];mov     [rax], dl;jmp loc_4006E3;\
                            loc_size_2:mov     rax, [rbp-8];mov     edx, eax;mov     rax, [rbp-38h];mov     [rax], dx;\
                            jmp loc_4006E3;loc_size_4:mov     rax, [rbp-8];mov     edx, eax;mov     rax, [rbp-38h];\
                            mov     [rax], edx;jmp loc_4006E3;loc_size_8:mov     rdx, [rbp-8];mov     rax, [rbp-38h];\
                            mov     [rax], rdx;loc_4006E3:pop     rbp;ret;"

#define TRUNC_HELPER_CODE       "push    rbp;mov     rbp, rsp;mov     [rbp-18h], rdi;mov     eax, edx;mov     [rbp-28h], rcx;mov     [rbp-1Ch], si; \
                           mov     [rbp-20h], ax; movzx   eax, word ptr [rbp-20h];mov     edx, 8;sub     edx, eax;mov     eax, edx;shl     eax, 3; \
                           mov     rdx, [rbp-18h];mov     ecx, eax;shl     rdx, cl;mov     rax, rdx;mov     [rbp-10h], rax; \
                           movzx   eax, word ptr [rbp-20h];mov     edx, 8;sub     edx, eax;mov     eax, edx;shl     eax, 3; \
                           mov     rdx, [rbp-10h];mov     ecx, eax;shr     rdx, cl;mov     rax, rdx;mov     [rbp-8], rax; \
                           movzx   eax, word ptr [rbp-1Ch];cmp     eax, 2;jz      loc_40061B;cmp     eax, 2;jg      loc_400601; \
                           cmp     eax, 1;jz      loc_40060D;jmp     loc_400644;loc_400601:cmp     eax, 4;jz      loc_40062A; \
                           cmp     eax, 8;jz      loc_400638;jmp     loc_400644;loc_40060D:mov     rax, [rbp-8];mov     edx, eax; \
                           mov     rax, [rbp-28h];mov     [rax], dl;jmp    loc_400644;loc_40061B:mov     rax, [rbp-8];mov     edx, eax; \
                           mov     rax, [rbp-28h];mov     [rax], dx;jmp    loc_400644;loc_40062A:mov     rax, [rbp-8];mov     edx, eax; \
                           mov     rax, [rbp-28h];mov     [rax], edx;jmp    loc_400644;loc_400638:mov     rdx, [rbp-8];mov     rax, [rbp-28h]; \
                           mov     [rax], rdx;loc_400644:pop     rbp;ret;"

#define HELPERS CONCAT_HELPER_NAME":"CONCAT_HELPER_CODE""TRUNC_HELPER_NAME":"TRUNC_HELPER_CODE

#define DEFAULT_CODE_GEN_BUFFER_SIZE (1 * (INT64_C(1) << 20)) //1Mb

void *code_gen_mmap;

int code_gen_index=0;

void (*concat_func)(long long unsigned int op1,short unsigned int op1_size,long long unsigned int op2,short unsigned int op2_size,short unsigned int concat_size,void *retaddr);

void (*trunc_func)(long long unsigned int op,short unsigned int orig_size,short unsigned int trunc_size,void *retaddr);

long unsigned int(*slice)(char *input, int num_bytes);

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

int initialize_executable_file(char *file_name){
    int fd = open(file_name, O_RDWR|O_CREAT);
    if (fd == -1){
        printf("error openning file:%s\n",file_name);
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
    return fd;
}

int test_helper_calls(){
    int fd = open("asm_map", O_RDWR|O_CREAT, 0777);
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

long long unsigned int slice_func(char *input){
    int i=0;
    if(input!=NULL){
        i=1;
        printf("var i=%p, input=%p, input[0]=%c\n",&i,input,input[0]);
    }
    return 0xdeadbeaf;
}

void stub_func(char *input, int num_bytes, void *gen_asm_ptr){ //if input is larger, a new stub should be written
    long long unsigned int ret = 0;
    char taints[1024]={'\0'};
    if(num_bytes>1024){
        printf("you should write your own stub, if larger input than %d is needed!\n",1024);
        assert(0);
    }
    for (int i=0;i<num_bytes;i++){
        taints[1023-i] = input[num_bytes-1-i];
    }
//    printf("taints_addr=%p\n",taints);
    slice = gen_asm_ptr;
    ret = slice(input,num_bytes);
    printf("ret=%llx\n",ret);
}

int test_sample_slice(){
    const char *asm_file = "sample_generated_asm.asm";
    struct stat st;
    int fd_asm = open(asm_file, O_RDWR);
    if (fd_asm == -1){
        printf("error openning file=%s\n",asm_file);
        exit(1);
    }
    if (fstat(fd_asm, &st) < 0) {
        return -errno;
    }
    char *asm_gen_code= (char *)mmap(NULL,st.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd_asm, 0);
    printf("assembly code:\n");
    for (int i=0;i<st.st_size;i++){
        printf("%c",asm_gen_code[i]);
    }
    printf("\n");
    int ex_fd=initialize_executable_file("asm_map");
    unsigned char *encode=NULL;
    size_t size = 0; //num of compiled bytes as  returned by keystone
    test_ks(encode, &size,asm_gen_code);

    printf("Executing the assembled instructions for the sample slice...\n");

    char input[8]={'K','\0','4','\0','\0','\0','\0','\0'}; //since we set 8 for init_asm_generation, and my system allocates 2 bytes per input char
    stub_func(input,8,code_gen_mmap);
    close(ex_fd);
    close(fd_asm);
    return 0;
}
char slice_inputs[32]={'\0'};
int main(){
    return test_sample_slice();
}