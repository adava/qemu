//
// Created by sina on 4/28/20.
//

//TODO the flags effect is not properly propagated

//#define DEBUG_MEMCB
//#define LOG_INS
//#define DEBUG_CB
#define DEBUG_SYSCALL 0
//#define NBENCH_EVALUATION

//uint64_t debug_ip = 0;

#include <stdlib.h>
#include <qemu-plugin.h>
#include "shadow_memory.h"
#include "lib/tainting.h"
#include "dfsan_interface.h"
//#include "dfsan.h"
//#include "lib/DFSan/dfsan.c" have to provide the library at compile time

#ifdef NBENCH_EVALUATION
#include "nbench_instrument.c"
#endif

#define FLAG_REG 100 //assumes that flags are modeled via a single register with ID 100. Since we have only 92 mapped registers, value 100 is fine

#define get_taint(src) (src.type==GLOBAL || src.type==GLOBAL_IMPLICIT)?dfsan_get_register_label(src.addr.id):dfsan_read_label((void *)src.addr.vaddr,src.size)
#define set_taint(dst,val) \
        if(dst.type==GLOBAL || dst.type==GLOBAL_IMPLICIT){ \
            dfsan_set_register_label(dst.addr.id,val); \
        } else if(dst.type==MEMORY || dst.type==MEMORY_IMPLICIT) dfsan_set_label(val,(void *)dst.addr.vaddr,dst.size);

static void taint_cb_clear_all(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_clear_all");

    if(arg->src.addr.vaddr && arg->src.type!=UNASSIGNED){
        set_taint(arg->src,CONST_LABEL);
    }
    if(arg->src2.addr.vaddr && arg->src2.type!=UNASSIGNED){
        set_taint(arg->src2,CONST_LABEL);
    }
    if(arg->src3.addr.vaddr && arg->src3.type!=UNASSIGNED){
        set_taint(arg->src3,CONST_LABEL);
    }
    if(arg->dst.addr.vaddr && arg->dst.type!=UNASSIGNED){
        set_taint(arg->dst,CONST_LABEL);
    }

}

static void taint_cb_mov(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_mov");

    dfsan_label label = arg->src.type!=IMMEDIATE? get_taint(arg->src): CONST_LABEL; //The immediate check is kinda redundant, since we are already clearing in taint_cb_clear if immediate
    set_taint(arg->dst,label);

}

static void taint_cb_mov2(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata);
    if(arg->src.type==UNASSIGNED || arg->src2.type==UNASSIGNED || arg->src3.type==UNASSIGNED || arg->dst.type==UNASSIGNED){
        AOUT("use taint_cb_mov function instead!");
        assert(1);
    }
    dfsan_label label = arg->src.type!=IMMEDIATE? get_taint(arg->src): CONST_LABEL;
    set_taint(arg->dst,label);

    dfsan_label label2 = arg->src2.type!=IMMEDIATE? get_taint(arg->src2): CONST_LABEL;
    set_taint(arg->src3,label2);
}

static void taint_cb_movwf(unsigned int cpu_index, void *udata){ //could have used mov2 but this one incurs one less label query
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

static void taint_cb_2ops(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_2ops");

//    shad_inq flags={.addr.id=FLAG_REG,.type=GLOBAL_IMPLICIT};

    dfsan_label l1 = (arg->src.type==IMMEDIATE || arg->src.type==UNASSIGNED)?CONST_LABEL: get_taint(arg->src); //in case of IMUL with 3 ops, the src can be IMM.
    dfsan_label l2 = (arg->src2.type==IMMEDIATE || arg->src2.type==UNASSIGNED)?CONST_LABEL: get_taint(arg->src2);  //for SETcc, type is UNASSIGNED

    if(arg->src2.type==MEMORY && arg->dst.type==MEMORY_IMPLICIT){ //ADD and FP instructions
        arg->dst.addr.vaddr = arg->src2.addr.vaddr;
    }

    dfsan_label dst_label = CONST_LABEL;
    if(l1!=CONST_LABEL || l2!=CONST_LABEL){
        dst_label = dfsan_union(l1, l2, arg->operation, arg->src.size,
                                  arg->src.addr.vaddr, arg->src2.addr.vaddr, arg->src.type, arg->src2.type, arg->dst.addr.vaddr,  arg->dst.type);
    }
    set_taint(arg->dst,dst_label);

}
//support the union of up to three operands
static void taint_cb_3ops(unsigned int cpu_index, void *udata){ //TODO you might need to take care of flags
    shadow_err err = 0;
    INIT_ARG(arg,udata);
#define cb_debug "taint_cb_3ops"
    DEBUG_OUTPUT(arg,cb_debug);
    if(arg->src.type==UNASSIGNED || arg->src2.type==UNASSIGNED || arg->src3.type==UNASSIGNED){
        AOUT("use taint_cb_2ops function instead!");
        assert(1);
    }
    dfsan_label l1 = (arg->src.type==IMMEDIATE)?  CONST_LABEL: get_taint(arg->src);
    dfsan_label l2 = (arg->src2.type==IMMEDIATE)? CONST_LABEL: get_taint(arg->src2);
    dfsan_label l3 = (arg->src3.type==IMMEDIATE)? CONST_LABEL: get_taint(arg->src3);

    if(arg->src3.type==MEMORY && arg->dst.type==MEMORY_IMPLICIT){ //ADC and FP instructions with 3 ops, the address was read in the mem_cb
        arg->dst.addr.vaddr = arg->src3.addr.vaddr;
    }

    dfsan_label l4 = CONST_LABEL;
    dfsan_label dst_label = CONST_LABEL;

    if(l1!=CONST_LABEL || l2!=CONST_LABEL || l3!=CONST_LABEL){
        l4 = dfsan_union(l2, l3, 0 , 0,
                                      arg->src2.addr.vaddr, arg->src3.addr.vaddr, arg->src2.type, arg->src3.type, 0, UNASSIGNED); //we need the union regardless of l2/l3 status because dst looks for multiple_ops
        dst_label = dfsan_union(l1, l4, arg->operation, arg->src.size,
                                  arg->src.addr.vaddr, 0, arg->src.type, MULTIPLE_OPS, arg->dst.addr.vaddr,  arg->dst.type);
    }
    set_taint(arg->dst,dst_label);

    OUTPUT_ERROR(err,arg,cb_debug);
}


static void taint_cb_XCHG(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
#define cb2_debug "taint_cb_XCHG"
    DEBUG_OUTPUT(arg,cb2_debug);

    dfsan_label label1 = arg->src.type!=IMMEDIATE? get_taint(arg->src): 0;
    dfsan_label label2 = arg->src.type!=IMMEDIATE? get_taint(arg->dst): 0;

    if(label1!=CONST_LABEL || label2!=CONST_LABEL){
        set_taint(arg->src,label2);
        set_taint(arg->dst,label1);

    }

    OUTPUT_ERROR(err,arg,cb2_debug);
}

/* This is a precise rule; through unions, we force having either the previous taint status (if any) or taking CMPCHG result*/
static void taint_cb_CMPCHG(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_CMPCHG");
    shad_inq regEAX = {.addr.id=MAP_X86_REGISTER(X86_REG_RAX),.type=GLOBAL_IMPLICIT};

    dfsan_label l1 = get_taint(arg->src); //dst=src (if eax==dst)
    dfsan_label l2 = get_taint(arg->dst);
    dfsan_label l3 = get_taint(regEAX); //eax=dst (if eax!=dst) part that we conservatively propagate
    dfsan_label xchg_label = CONST_LABEL;
    if(l1!=CONST_LABEL || l2!=CONST_LABEL || l3!=CONST_LABEL) {
        dfsan_label l4 =  dfsan_union(l2, l3, 0, 0,
                                        arg->dst.addr.vaddr, regEAX.addr.id, arg->dst.type, regEAX.type, 0, UNASSIGNED);
        xchg_label = dfsan_union(l1, l4, arg->operation, arg->src.size,
                                               arg->src.addr.vaddr, 0, arg->src.type, MULTIPLE_OPS, 0,
                                               UNASSIGNED); //Since multiple destinations are affected, I mark destination type as UNASSIGNED
    }
    else{
        return; //propagation of CONST_LABEL is redundant
    }
    //either eax=dst branch executes that results in dst taint being loaded, or doesn't that previous eax holds
    if(l3!=CONST_LABEL || l2!=CONST_LABEL){ //otherwise EAX remains not tainted
        set_taint(regEAX,xchg_label);
        OUTPUT_ERROR(err,arg,"CMPCHG propagate from dst to EAX");
    }
    if(l1!=CONST_LABEL || l2!=CONST_LABEL) { //otherwise dst remains not tainted
        set_taint(arg->dst,xchg_label); // we conservatively propagate; note that for xchg_label, we first load dst with its previous load (left branch of MULTIPLE_OPS)
        OUTPUT_ERROR(err,arg,"CMPCHG propagate from src to dst");
    }
}

static void taint_cb_MUL_DIV(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
#define cb3_debug "taint_cb_MUL_DIV"

    DEBUG_OUTPUT(arg,cb3_debug);

    dfsan_label l1 = get_taint(arg->src);
    dfsan_label l2 = get_taint(arg->src2); //eax

    dfsan_label l3 = get_taint(arg->src3); //edx

    if(l1==CONST_LABEL && l2==CONST_LABEL){ //no propagation
        return;
    }

    dfsan_label l4 =  dfsan_union(l1, l2, arg->operation, arg->src.size,
                                    arg->src.addr.vaddr, arg->src2.addr.vaddr, arg->src.type, arg->src2.type, 0, UNASSIGNED); //both EAX and EDX would be affected as destination

    set_taint(arg->dst,l4); // eax part of mul/div

    arg->dst.addr.id = arg->src3.addr.id;

    dfsan_label l6 = ((l3 == CONST_LABEL)? l4 : dfsan_union(l3, l4, 0, 0, 0, 0, UNASSIGNED, UNASSIGNED, arg->dst.addr.vaddr, arg->dst.type)); //l3 is not part of l4, hence union
    set_taint(arg->dst,l6); // edx part of mul/div

    shad_inq flags={.addr.id=FLAG_REG,.type=GLOBAL};
    set_taint(flags,l4);

    OUTPUT_ERROR(err,arg,cb3_debug);
}

static void taint_cb_JUMP(unsigned int cpu_index, void *udata) {
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_JUMP");

    dfsan_label jmp_addr = 0;
    if(arg->src.type != IMMEDIATE){
        jmp_addr = get_taint(arg->src);
        OUTPUT_ERROR(jmp_addr,arg,"JUMP *** address 0x%lx is tainted ***");
    }
    if(arg->operation==COND_JMP){
        shad_inq flags={.addr.id=FLAG_REG,.type=GLOBAL};
        dfsan_label flags_shadow = get_taint(flags);
        OUTPUT_ERROR(flags_shadow!=0,arg,"JUMP *** flags are tainted ***"); //in fact, this is where we should flip a branch
    }
}

static void taint_cb_CALL(unsigned int cpu_index, void *udata) {
    INIT_ARG(arg,udata);
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
    OUTPUT_ERROR(jmp_addr,arg,"CALL *** destination function address is tainted ***");
}

static void taint_cb_RET(unsigned int cpu_index, void *udata) { //reverse of CALL, RET target is read from stack
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_RET");

    READ_VALUE(arg->src, &arg->src.addr.vaddr);
    arg->src.type = MEMORY;
    dfsan_label l1 = get_taint(arg->src); //esp

    set_taint(arg->dst,l1); //eip

    //check the destination address
    OUTPUT_ERROR(l1,arg,"RET *** destination function address is tainted ***");
}

static void taint_cb_LEAVE(unsigned int cpu_index, void *udata){ //TODO double check whether top of stack is read before LEAVE instruction
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