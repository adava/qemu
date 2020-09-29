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

#include "bin_gen.h"

void *code_gen_mmap;

int code_gen_index=0;

int initialize_executable_file(char *file_name){
    int fd = open(file_name, O_RDWR|O_CREAT,0777);
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

void* assemble_and_write(unsigned char *encode, size_t *size, char *CODE){ //*encode is for further reference, the executable is at code_gen_mmap
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
    return code_gen_mmap;
}
//returns a pointer to the executable slice, see slice_func type
void* executable_from_asm(char *asm_file, char **asm_code, int *asm_code_size, size_t *assembled_size){
    struct stat st;
    int fd_asm = open(asm_file, O_RDWR);
    if (fd_asm == -1){
        printf("error openning file=%s\n",asm_file);
        assert(0);
    }
    if (fstat(fd_asm, &st) < 0) {
        printf("fstat error=%s\n",strerror(errno));
        assert(0);
    }
    *asm_code_size = st.st_size;
    *asm_code= (char *)mmap(NULL,st.st_size, PROT_READ, MAP_PRIVATE, fd_asm, 0);
    int ex_fd=initialize_executable_file("asm_map");
    unsigned char *encode=NULL;
    void *exec_addr=assemble_and_write(encode, assembled_size,*asm_code);

    close(ex_fd);
    close(fd_asm);
    return exec_addr;
}