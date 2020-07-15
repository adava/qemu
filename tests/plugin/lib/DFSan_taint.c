//
// Created by sina on 4/28/20.
//
//#define DEBUG_MEMCB
//#define LOG_INS
//#define DEBUG_CB
#define DEBUG_SYSCALL 0
//#define NBENCH_EVALUATION

//uint64_t debug_ip = 0;

#include <stdlib.h>
#include <qemu-plugin.h>
#include "lib/tainting.h"
#include "../lib/DFSan/dfsan_interface.h"
#include "../lib/DFSan/dfsan.h"
#include "lib/DFSan/dfsan.c"
#ifdef NBENCH_EVALUATION
#include "nbench_instrument.c"
#endif

#define FLAG_REG 100 //assumes that flags are modeled via a single register with ID 100. Since we have only 92 mapped registers, value 100 is fine

#define get_taint(src) src.type==GLOBAL?dfsan_get_register_label(src.addr.id):dfsan_read_label((void *)src.addr.vaddr,src.size)
#define set_taint(dst,val) \
        if(dst.type==GLOBAL){ \
            dfsan_set_register_label(dst.addr.id,val); \
            dfsan_set_label(val,(void *)dst.addr.vaddr,dst.size); \
            }

static void mark_input_bytes(uint64_t *addr, int64_t ret){
    for(int i=0;i<ret;i++){
        char *desc = malloc(20);
        sprintf(desc,"%d",i);
        dfsan_label label = dfsan_create_label(desc,(void *)0);
        dfsan_set_label(label, addr+i, 1);
    }
//    printf("exiting mark_input\n");
}

static void taint_cb_clear(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_clear");
    set_taint(arg->dst,0);
}

static void taint_cb_clear_all(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_clear_all");

    set_taint(arg->dst,0);

    if(arg->src.addr.vaddr){
        set_taint(arg->dst,0);
    }
    if(arg->src2.addr.vaddr){
        set_taint(arg->dst,0);
    }
    if(arg->src3.addr.vaddr){
        set_taint(arg->dst,0);
    }
    if(arg->dst.addr.vaddr){
        set_taint(arg->dst,0);
    }

}

static void taint_cb_mov(unsigned int cpu_index, void *udata){ //use taint_cb prefix instead of SHD
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_mov");

    dfsan_label label = arg->src.type!=IMMEDIATE? get_taint(arg->src): 0;
    set_taint(arg->dst,label);

}

static void taint_cb_mov2(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);

    dfsan_label label = arg->src.type!=IMMEDIATE? get_taint(arg->src): 0;
    set_taint(arg->dst,label);

    dfsan_label label2 = arg->src2.type!=IMMEDIATE? get_taint(arg->src2): 0;
    set_taint(arg->src3,label2);

    OUTPUT_ERROR(err,arg,"SYSCALL");
}

static void taint_cb_movwf(unsigned int cpu_index, void *udata){ //use taint_cb prefix instead of SHD
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_movwf");

    dfsan_label label = arg->src.type!=IMMEDIATE? get_taint(arg->src): 0;
    set_taint(arg->dst,label);
    OUTPUT_ERROR(err,arg,"MOV");

    shad_inq flags={.addr.id=FLAG_REG,.type=GLOBAL};
    set_taint(flags,label);

    OUTPUT_ERROR(err,arg,"MOV flags propagation");
}

static void taint_cb_ADD_SUB(unsigned int cpu_index, void *udata){ //support the union of up to three operands
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_ADD_SUB");

    dfsan_label l1 = arg->src.type!=IMMEDIATE? get_taint(arg->src): 0;
    dfsan_label l2 = arg->src2.type!=IMMEDIATE? get_taint(arg->src2): 0;
    dfsan_label l3 = 0;
    if(l1!=0 && l2!=0){
        l3 = dfsan_union(l1, l2);
    }
    else{
        l3 = l1 + l2; //l3 would be equal to which ever that is not zero
    }
    if (arg->src3.addr.vaddr!=0 && arg->src3.type!=IMMEDIATE){ //to support instructions with 4 operands
        dfsan_label l4 = get_taint(arg->src3);
        l3 = dfsan_union(l3, l4);
    }
    set_taint(arg->dst,l3);

    OUTPUT_ERROR(err,arg,"ADD/SUB");
}

static void taint_cb_XCHG(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_XCHG");

    dfsan_label label1 = arg->src.type!=IMMEDIATE? get_taint(arg->src): 0;
    dfsan_label label2 = arg->src.type!=IMMEDIATE? get_taint(arg->dst): 0;

    set_taint(arg->src,label2);
    set_taint(arg->dst,label1);

    OUTPUT_ERROR(err,arg,"XCHG");
}

/* A precise rule would need reading RAX and destination value before this instruction.
 * Here, we approximate by propagating based on either results of the instruction execution. */
static void taint_cb_CMPCHG(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_CMPCHG");
    shad_inq regEAX = {.addr.id=MAP_X86_REGISTER(X86_REG_RAX),.type=GLOBAL};

    dfsan_label l1 = get_taint(arg->dst);
    dfsan_label l2 = get_taint(regEAX);
    dfsan_label l3 = dfsan_union(l1, l2);
    set_taint(arg->dst,l3); //if eax=dst part that we conservatively propagate

    OUTPUT_ERROR(err,arg,"CMPCHG propagate from dst to EAX");

    dfsan_label l4 = get_taint(arg->src);
    dfsan_label l5 = dfsan_union(l4, l3);
    set_taint(arg->dst,l5); //else src=dst that again we conservatively propagate

    OUTPUT_ERROR(err,arg,"CMPCHG propagate from src to dst");
}

static void taint_cb_MUL_DIV(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_MUL_DIV");
    arg->dst.type = GLOBAL;
    arg->dst.addr.id = arg->src2.addr.id;

    dfsan_label l1 = get_taint(arg->src);
    dfsan_label l2 = get_taint(arg->src2); //eax
    dfsan_label l3 = dfsan_union(l1, l2);
    set_taint(arg->dst,l3); // eax part of mul/div

    arg->dst.addr.id = arg->src3.addr.id;

    dfsan_label l4 = get_taint(arg->src3); //edx
    dfsan_label l5 = dfsan_union(l1, l4);
    set_taint(arg->dst,l5); // edx part of mul/div

    shad_inq flags={.addr.id=FLAG_REG,.type=GLOBAL};
    set_taint(flags,l5);

    OUTPUT_ERROR(err,arg,"Mul");
}

static void taint_cb_JUMP(unsigned int cpu_index, void *udata) {
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_JUMP");

    dfsan_label jmp_addr = 0;
    if(arg->src.type != IMMEDIATE){
        jmp_addr = get_taint(arg->src);
    }
    jmp_addr!=0?(err=1):(err=0);
    OUTPUT_ERROR(err,arg,"JUMP *** address 0x%lx is tainted ***");
    if(arg->operation==COND_JMP){
        shad_inq flags={.addr.id=FLAG_REG,.type=GLOBAL};
        dfsan_label flags_shadow = get_taint(flags);
        OUTPUT_ERROR(flags_shadow!=0,arg,"JUMP *** flags are tainted ***");
    }
//    printf("finished JUMP CB\n");
}

static void taint_cb_CALL(unsigned int cpu_index, void *udata) {
    shadow_err err = 0;
    INIT_ARG(arg,udata);
//    printf("taint_cb_CALL\n");
    DEBUG_OUTPUT(arg,"taint_cb_CALL");
    READ_VALUE(arg->dst, &arg->dst.addr.vaddr); //we need the value of stack register, we use the value as a memory address to store the eip taint
    arg->dst.type = MEMORY;

    dfsan_label l1 = get_taint(arg->src2); //eip
    set_taint(arg->dst,l1);

    //check the destination address
    dfsan_label jmp_addr = 0;

    if(arg->src.type != IMMEDIATE){
        jmp_addr = get_taint(arg->src);
    }
    jmp_addr!=0?(err=1):(err=0);
    OUTPUT_ERROR(err,arg,"CALL *** destination function address is tainted ***");
//    printf("leaving taint_cb_CALL\n");
}

static void taint_cb_RET(unsigned int cpu_index, void *udata) { //reverse of CALL, RET target is one put in the dst read from stack
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_RET");

    READ_VALUE(arg->src, &arg->src.addr.vaddr);
    arg->src.type = MEMORY;
    dfsan_label l1 = get_taint(arg->src); //esp

    set_taint(arg->dst,l1); //eip

    //check the destination address
    l1!=0?(err=1):(err=0);
    OUTPUT_ERROR(err,arg,"RET *** destination function address is tainted ***");
}

static void taint_cb_LEAVE(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata);

    DEBUG_OUTPUT(arg,"taint_cb_LEAVE");

    dfsan_label l1 = get_taint(arg->src2); //RBP to RSP
    set_taint(arg->dst,l1);

    dfsan_label l2 = get_taint(arg->src); //MEM shadow to RBP
    set_taint(arg->src2,l2);

}

static void taint_list_all(void){
    report = g_string_new("------Listing register shadows------\n");
    //memory regs
    g_string_append_printf(report,"----------------------------------\n");

    g_string_append_printf(report,"------Listing memory shadows------\n");
    //memory addrs
    g_string_append_printf(report,"----------------------------------\n");

    qemu_plugin_outs(report->str);
}

#ifdef CONFIG_2nd_CCACHE
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    tb_ip *tbIp = (tb_ip *)udata;
//    debug_ip = tbIp->ip;
    shadow_err err;
#ifdef NBENCH_EVALUATION
    taint_nbench_arginregs(tbIp->ip, LoadNumArrayWithRand_exit_bb,sort_array_reg,sort_size_reg);
    taint_nbench_str(tbIp->ip, LoadStringArray_exit_bb);
    taint_nbench_arginregs(tbIp->ip, DoBitfieldIteration_exit_bb,bf_array_reg,bf_size_reg);
    taint_nbench_arginregs(tbIp->ip, SetupCPUEmFloatArrays_exit_bb,fem_array_reg,fem_size_reg);
    taint_nbench_arginregs(tbIp->ip, DoFPUTransIteration_exit_bb,fp_array_reg,fp_size_reg);
    taint_nbench_arginreg_fix(tbIp->ip, LoadAssign_exit_bb,la_array_reg,la_array_size);
    taint_nbench_arginreg_fix(tbIp->ip, DoIDEA_exit_bb,id_array_reg,id_array_size);
    taint_nbench_arginregs(tbIp->ip, createtextline_exit_bb,HM_array_reg,HM_size_reg);
//    taint_nbench_array(tbIp->ip, createtextline_exit_bb, HM_array_stack_offset, HM_size_stack_offset);

#endif
    if(second_ccache_flag==TRACK){
        err = check_registers(R_EAX,R_EIP);
        if (err==0){
#ifdef CONFIG_DEBUG_CCACHE_SWITCH
            printf("registers clean for tb=%d, ip=%lx\n",tbIp->tb,tbIp->ip);
#endif
            switch_mode(CHECK,true,tbIp->ip);
        }
    }
}
#endif