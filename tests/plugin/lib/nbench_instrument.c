//
// Created by sina on 2020-06-29.
//


#define LoadNumArrayWithRand_exit_bb 0x406E99
#define sort_array_reg MAP_X86_REGISTER(X86_REG_R12) //the first function argument at rdi is copied to r12
#define sort_size_reg  MAP_X86_REGISTER(X86_REG_RBP) //the second function argument at rsi is copied to rbp
#define LoadStringArray_exit_bb 0x407463
#define str_array_reg MAP_X86_REGISTER(X86_REG_R14) //Initially stringarray is in rdi but it would be copied to r14
#define str_size_stack_offset  0x8 //Initially size is in rdx but it would be copied to rsp + 8
#define DoBitfieldIteration_exit_bb 0x404310
#define bf_array_reg MAP_X86_REGISTER(X86_REG_R13) //rsi seems to contain the second parameter that is the mem addr, rsi is copied to r13
#define bf_size_reg  MAP_X86_REGISTER(X86_REG_RBP) //rdx seems to contain the third parameter that is the mem size, rdx is copied to rbp
#define DoFPUTransIteration_exit_bb 0x4069A4
#define fp_array_reg MAP_X86_REGISTER(X86_REG_R12) //RDI (first param) is copied to R12
#define fp_size_reg  MAP_X86_REGISTER(X86_REG_R13) //RDX (third param) is copied to R13
#define LoadAssign_exit_bb 0x4085EA
#define la_array_reg MAP_X86_REGISTER(X86_REG_RBX) //it's an inline function and seems rbx has it
#define la_array_size  0x65
#define DoIDEA_exit_bb 0x408AA9
#define id_array_reg MAP_X86_REGISTER(X86_REG_RBX)
#define id_array_size  0x8
#define SetupCPUEmFloatArrays_exit_bb 0x402D30
#define fem_array_reg MAP_X86_REGISTER(X86_REG_RBX) //RDI (first param) is copied to RBX
#define fem_size_reg  MAP_X86_REGISTER(X86_REG_R13) //RCX (fourth param) is copied to R13
#define createtextline_exit_bb 0x409500
#define HM_array_stack_offset 0x30
#define HM_size_stack_offset  0x38

//The key is to know what memory location/register has the pointer to the array

void taint_nbench_arginregs(uint64_t current_ip, uint64_t bb_addr, uint32_t addr_reg, uint32_t size_reg){
    if(current_ip==bb_addr){
        uint64_t mem_addr=0;
        shad_inq inq1 = {.type=GLOBAL, .addr.id=addr_reg,.size=SHD_SIZE_u64};
        READ_VALUE(inq1,&mem_addr);

        uint64_t mem_size=0;
        shad_inq inq2 = {.type=GLOBAL, .addr.id=size_reg,.size=SHD_SIZE_u64};
        READ_VALUE(inq2,&mem_size);

        uint8_t value = 0xff;
        SHD_write_contiguous(mem_addr, mem_size, value);
//        printf("addr=0x%lx, size=0x%lx\n",mem_addr,mem_size);
    }
}

void taint_nbench_arginreg_fix(uint64_t current_ip,uint64_t bb_addr,uint32_t addr_reg, uint32_t mem_size){
    if(current_ip==bb_addr){
        uint64_t mem_addr=0;
        shad_inq inq1 = {.type=GLOBAL, .addr.id=addr_reg,.size=SHD_SIZE_u64};
        READ_VALUE(inq1,&mem_addr);

        uint8_t value = 0xff;
        SHD_write_contiguous(mem_addr, mem_size, value);
//        printf("addr=0x%lx, size=0x%x\n",mem_addr,mem_size);
    }
}


void taint_nbench_str(uint64_t current_ip, uint64_t bb_addr){
    if(current_ip==bb_addr){
        uint64_t mem_addr=0;
        shad_inq inq1 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_R14),.size=SHD_SIZE_u64};
        READ_VALUE(inq1,&mem_addr);

        uint64_t r_rsp=0;
        shad_inq inq2 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_RSP),.size=SHD_SIZE_u64};
        READ_VALUE(inq2,&r_rsp);

        uint64_t r_ss=0;
        shad_inq inq3 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_SS),.size=SHD_SIZE_u64};
        READ_VALUE(inq3,&r_ss);

        uint64_t mem_size=0;
        shad_inq mem_size_inq = {.type=MEMORY, .addr.vaddr=r_ss+r_rsp+8,.size=SHD_SIZE_u64};
        READ_VALUE(mem_size_inq,&mem_size);

        uint8_t value = 0xff;
        SHD_write_contiguous(mem_addr, mem_size, value);
//        printf("addr=0x%lx, size=0x%lx\n",mem_addr,mem_size);
    }
}

//#ifdef NBENCH_EVALUATION
//#define LoadNumArrayWithRand_exit_bb 0x406E99
//#define sort_array_stack_offset 0x18
//#define sort_size_stack_offset  0x20
//#define LoadStringArray_exit_bb 0x407463
//#define str_array_stack_offset 0x90
//#define str_size_stack_offset  0x98
//#define DoBitfieldIteration_exit_bb 0x404310
//#define bf_array_stack_offset 0x8
//#define bf_size_stack_offset  0x0
//#define DoFPUTransIteration_exit_bb 0x4069A4
//#define fp_array_stack_offset 0x48
//#define fp_size_stack_offset  0x40
//#define LoadAssign_exit_bb 0x4044DB
//#define la_array_stack_offset 0x0
//#define fp_array_size  0x65
//#define DoIDEA_exit_bb 0x408AB7
//#define id_array_stack_offset 0x40
//#define id_array_size  0x8
//#define SetupCPUEmFloatArrays_exit_bb 0x402D40
//#define fem_array_stack_offset 0x8
//#define fem_size_stack_offset  0x0
//#define createtextline_exit_bb 0x40951A
//#define HM_array_stack_offset 0x30
//#define HM_size_stack_offset  0x38
//#endif

//the below were usefull for debugging and validation. The nbench should contain a printout of the
//interesting variables. The addresses above are based on on function being debugged. Otherwise, addresses would change
//Below is the usage:
//    taint_nbench_array(tbIp->ip, LoadNumArrayWithRand_exit_bb, sort_array_stack_offset, sort_size_stack_offset);
//    taint_nbench_array(tbIp->ip, LoadStringArray_exit_bb, str_array_stack_offset, str_size_stack_offset);
//    taint_nbench_array(tbIp->ip, DoBitfieldIteration_exit_bb, bf_array_stack_offset, bf_size_stack_offset);
//    taint_nbench_array(tbIp->ip, SetupCPUEmFloatArrays_exit_bb, fem_array_stack_offset, fem_size_stack_offset);
//    taint_nbench_array(tbIp->ip, DoFPUTransIteration_exit_bb, fp_array_stack_offset, fp_size_stack_offset);
//    taint_nbench_fix(tbIp->ip, LoadAssign_exit_bb, la_array_stack_offset, fp_array_size);
//    taint_nbench_stack(tbIp->ip, DoIDEA_exit_bb, id_array_stack_offset, id_array_size);
//    taint_nbench_array(tbIp->ip, createtextline_exit_bb, HM_array_stack_offset, HM_size_stack_offset);

void taint_nbench_array(uint64_t current_ip,uint64_t bb_addr,uint32_t array_stack_offset,uint32_t size_stack_offset){
    if(current_ip==bb_addr){
        uint64_t r_rsp=0;
        shad_inq inq1 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_RSP),.size=SHD_SIZE_u64};
        READ_VALUE(inq1,&r_rsp);

        uint64_t r_ss=0;
        shad_inq inq2 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_SS),.size=SHD_SIZE_u64};
        READ_VALUE(inq2,&r_ss);

        uint64_t mem_addr=0;
        shad_inq mem_addr_inq = {.type=MEMORY, .addr.vaddr=r_ss+r_rsp+array_stack_offset,.size=SHD_SIZE_u64};
        READ_VALUE(mem_addr_inq,&mem_addr);

        uint64_t mem_size=0;
        shad_inq mem_size_inq = {.type=MEMORY, .addr.vaddr=r_ss+r_rsp+size_stack_offset,.size=SHD_SIZE_u64};
        READ_VALUE(mem_size_inq,&mem_size);

        uint8_t value = 0xff;
        SHD_write_contiguous(mem_addr, mem_size, value);
//        printf("SS(%d)=0x%lx\tptr=0x%lx,  addr=0x%lx, size=0x%lx\n",MAP_X86_REGISTER(X86_REG_SS),r_ss,r_ss+r_rsp+array_stack_offset,mem_addr,mem_size);
    }
}

void taint_nbench_fix(uint64_t current_ip,uint64_t bb_addr,uint32_t array_stack_offset, uint64_t mem_size){
    if(current_ip==bb_addr){
        uint64_t r_rsp=0;
        shad_inq inq1 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_RSP),.size=SHD_SIZE_u64};
        READ_VALUE(inq1,&r_rsp);

        uint64_t r_ss=0;
        shad_inq inq2 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_SS),.size=SHD_SIZE_u64};
        READ_VALUE(inq2,&r_ss);

        uint64_t mem_addr=0;
        shad_inq mem_addr_inq = {.type=MEMORY, .addr.vaddr=r_ss+r_rsp+array_stack_offset,.size=SHD_SIZE_u64};
        READ_VALUE(mem_addr_inq,&mem_addr);

        uint8_t value = 0xff;
        SHD_write_contiguous(mem_addr, mem_size, value);
//        printf("SS(%d)=0x%lx\tptr=0x%lx,  addr=0x%lx, size=0x%lx\n",MAP_X86_REGISTER(X86_REG_SS),r_ss,r_ss+r_rsp+array_stack_offset,mem_addr,mem_size);
    }
}


void taint_nbench_stack(uint64_t current_ip,uint64_t bb_addr,uint32_t array_stack_offset, uint64_t mem_size){
    if(current_ip==bb_addr){
        uint64_t r_rsp=0;
        shad_inq inq1 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_RSP),.size=SHD_SIZE_u64};
        READ_VALUE(inq1,&r_rsp);

        uint64_t r_ss=0;
        shad_inq inq2 = {.type=GLOBAL, .addr.id=MAP_X86_REGISTER(X86_REG_SS),.size=SHD_SIZE_u64};
        READ_VALUE(inq2,&r_ss);

        uint64_t mem_addr=r_ss+r_rsp+array_stack_offset;

        uint8_t value = 0xff;
        SHD_write_contiguous(mem_addr, mem_size, value);
//        printf("SS(%d)=0x%lx\tptr=0x%lx,  addr=0x%lx, size=0x%lx\n",MAP_X86_REGISTER(X86_REG_SS),r_ss,r_ss+r_rsp+array_stack_offset,mem_addr,mem_size);
    }
}
