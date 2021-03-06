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

//#include "asm_generation.h"
//#include "dfsan.h"
//#include "lib/DFSan/dfsan.c" have to provide the library at compile time

#ifdef NBENCH_EVALUATION
#include "nbench_instrument.c"
#endif

#define get_taint(src) (src.type==GLOBAL || src.type==GLOBAL_IMPLICIT)?dfsan_get_register_label(src.addr.id):dfsan_read_label((void *)src.addr.vaddr,src.size)
#define set_taint(dst,val) \
        if(dst.type==GLOBAL || dst.type==GLOBAL_IMPLICIT){ \
            dfsan_set_register_label(dst.addr.id,val); \
        } else if(dst.type==MEMORY || dst.type==MEMORY_IMPLICIT) dfsan_store_label(val,(void *)dst.addr.vaddr,dst.size);
#define set_flags(flags,label)  if(flags.type!=UNASSIGNED) {\
                                        set_taint(flags,label);\
                                        }
#define Max(a, b) (((a) > (b)) ? (a) : (b))

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

    set_flags(arg->flags,label); //will only set flags if flags argument is set
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

static void taint_cb_2ops(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_2ops");

    dfsan_label l1 = (arg->src.type==IMMEDIATE || arg->src.type==UNASSIGNED)?CONST_LABEL: get_taint(arg->src); //in case of IMUL with 3 ops, the src can be IMM.
    dfsan_label l2 = (arg->src2.type==IMMEDIATE || arg->src2.type==UNASSIGNED)?CONST_LABEL: get_taint(arg->src2);  //for SETcc and MOVcc, type is UNASSIGNED

    if(arg->src2.type==MEMORY && arg->dst.type==MEMORY_IMPLICIT){ //ADD and FP instructions
        arg->dst.addr.vaddr = arg->src2.addr.vaddr;
    }

    dfsan_label dst_label = CONST_LABEL;
    if(l1!=CONST_LABEL || l2!=CONST_LABEL){
        dst_label = dfsan_union(l1, l2, arg->operation, arg->dst.size,
                                  arg->src.addr.vaddr, arg->src2.addr.vaddr, arg->src.type, arg->src2.type, arg->dst.addr.vaddr,  arg->dst.type);
    }
    set_taint(arg->dst,dst_label);

    set_flags(arg->flags,dst_label);

//    if ((int)arg->operation==(int)X86_INS_IMUL){ //debugging for the instructions appearing 5 times in the unrolled loop
//        printf("MUL/DIV eip=0x%lx, dst_label=%d\n",eip_val,dst_label);
//    }
    assert(arg->operation!=0);

}
//support the union of up to three operands
static void taint_cb_3ops(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
#define cb_debug "taint_cb_3ops"
    DEBUG_OUTPUT(arg,cb_debug);
    if(arg->src.type==UNASSIGNED || arg->src2.type==UNASSIGNED || arg->src3.type==UNASSIGNED){
        AOUT("use taint_cb_2ops function instead! OP=%d, operand1=%d, operand2=%d, operand3=%d\n",arg->operation, arg->src.type, arg->src2.type, arg->src3.type);
        assert(1);
    }
    dfsan_label l1 = (arg->src.type==IMMEDIATE || arg->src.type==UNASSIGNED)?  CONST_LABEL: get_taint(arg->src);
    dfsan_label l2 = (arg->src2.type==IMMEDIATE || arg->src2.type==UNASSIGNED)? CONST_LABEL: get_taint(arg->src2);
    dfsan_label l3 = (arg->src3.type==IMMEDIATE || arg->src3.type==UNASSIGNED)? CONST_LABEL: get_taint(arg->src3);

    if(arg->src3.type==MEMORY && arg->dst.type==MEMORY_IMPLICIT){ //ADC and FP instructions with 3 ops, the address was read in the mem_cb
        arg->dst.addr.vaddr = arg->src3.addr.vaddr;
    }

    dfsan_label l4 = CONST_LABEL;
    dfsan_label dst_label = CONST_LABEL;

    if(l1!=CONST_LABEL || l2!=CONST_LABEL || l3!=CONST_LABEL){

        //if const and implicit, no need to union
        enum shadow_type src_2_type;
        uint64_t src2;
        if((arg->src2.type==GLOBAL_IMPLICIT || arg->src2.type==MEMORY_IMPLICIT) && (l2==CONST_LABEL)){
            src_2_type = arg->src3.type;
            src2 = arg->src3.addr.vaddr;
            l4 = l3;
        }
        else if ((arg->src3.type==GLOBAL_IMPLICIT || arg->src3.type==MEMORY_IMPLICIT) && (l3==CONST_LABEL)){
            src_2_type = arg->src2.type;
            src2 = arg->src2.addr.vaddr;
            l4 = l2;
        }
        else{
            l4 = dfsan_union(l2, l3, UNION_MULTIPLE_OPS , arg->dst.size,
                             arg->src2.addr.vaddr, arg->src3.addr.vaddr, arg->src2.type, arg->src3.type, 0, MULTIPLE_OPS); //we need the union regardless of l2/l3 status because dst looks for multiple_ops
            src_2_type = MULTIPLE_OPS;
            src2 = 0;
        }
        dst_label = dfsan_union(l1, l4, arg->operation, arg->dst.size,
                                  arg->src.addr.vaddr, src2, arg->src.type, src_2_type, arg->dst.addr.vaddr,  arg->dst.type);
    }
    set_taint(arg->dst,dst_label);

    set_flags(arg->flags,dst_label);

    OUTPUT_ERROR(err,arg,cb_debug);
}


static void taint_cb_effmem(unsigned int cpu_index, void *udata){
    INIT_ARG(arg,udata); //src=index, src2=base, src3=scale and src4=disp

    dfsan_label l1 = (arg->src.type==IMMEDIATE || arg->src.type==UNASSIGNED)?  CONST_LABEL: get_taint(arg->src); //index
    dfsan_label l2 = (arg->src2.type==IMMEDIATE || arg->src2.type==UNASSIGNED)? CONST_LABEL: get_taint(arg->src2); //base
    dfsan_label l3 = CONST_LABEL;

    dfsan_label l4 = CONST_LABEL;
    dfsan_label l5 = CONST_LABEL;
    dfsan_label dst_label = CONST_LABEL;


    if(l1!=CONST_LABEL || l2!=CONST_LABEL){
        l3 = dfsan_union(l1, CONST_LABEL, UNION_MULTIPLE_OPS , arg->dst.size,
                         arg->src.addr.vaddr, arg->src3.addr.vaddr, arg->src.type, arg->src3.type, 0, MULTIPLE_OPS); //we need the union regardless of l1 status because of MULTIPLE_OPS

        l4 = dfsan_union(l2, CONST_LABEL, UNION_MULTIPLE_OPS , arg->dst.size,
                         arg->src2.addr.vaddr, arg->src4.addr.vaddr, arg->src2.type, arg->src4.type, 0, MULTIPLE_OPS); //we need the union regardless of l2 status


        l5 = dfsan_union(l3, l4, EFFECTIVE_ADDR_UNION, 0,
                         0, 0, MULTIPLE_OPS, MULTIPLE_OPS, 0,  EFFECTIVE_ADDR);

        dst_label = dfsan_union(l5, CONST_LABEL, arg->operation, arg->dst.size,
                                0, 0, EFFECTIVE_ADDR, UNASSIGNED, arg->dst.addr.vaddr,  arg->dst.type);

    }
    set_taint(arg->dst,dst_label);

    set_flags(arg->flags,dst_label);

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

    dfsan_label l1 = get_taint(arg->src); //dst=src (if eax==dst)
    dfsan_label l2 = get_taint(arg->dst);
    dfsan_label l3 = get_taint(arg->src2); //eax=dst (if eax!=dst) part that we conservatively propagate (EAX in src2)
    dfsan_label xchg_label_src2 = CONST_LABEL;
    dfsan_label xchg_label_dst = CONST_LABEL;
    if(l1!=CONST_LABEL || l2!=CONST_LABEL || l3!=CONST_LABEL) {
        dfsan_label l4 =  dfsan_union(l2, l3, UNION_MULTIPLE_OPS, arg->dst.size,
                                        arg->dst.addr.vaddr, arg->src2.addr.id, arg->dst.type, arg->src2.type, 0, MULTIPLE_OPS);
        xchg_label_dst = dfsan_union(l1, l4, arg->operation, arg->src.size,
                                               arg->src.addr.vaddr, 0, arg->src.type, MULTIPLE_OPS, arg->dst.addr.vaddr,
                                     arg->dst.type); //Since multiple destinations, I'll make two unions with different destinations; there should always be a destination since we will not know where the label came from
        xchg_label_src2 = dfsan_union(l1, l4, arg->operation, arg->src.size,
                                 arg->src.addr.vaddr, 0, arg->src.type, MULTIPLE_OPS, arg->src2.addr.vaddr,
                                      arg->src2.type);
    }
    else{
        return; //propagation of CONST_LABEL is redundant
    }
    //either eax=dst branch executes that results in dst taint being loaded, or doesn't that previous eax holds
    if(l3!=CONST_LABEL || l2!=CONST_LABEL){ //otherwise EAX remains not tainted
        set_taint(arg->src2,xchg_label_src2);
        OUTPUT_ERROR(err,arg,"CMPCHG propagate from dst to EAX");
    }
    if(l1!=CONST_LABEL || l2!=CONST_LABEL) { //otherwise dst remains not tainted
        set_taint(arg->dst,xchg_label_dst); // we conservatively propagate; note that for xchg_label, we first load dst with its previous load (left branch of MULTIPLE_OPS)
        OUTPUT_ERROR(err,arg,"CMPCHG propagate from src to dst");
    }

    set_flags(arg->flags,xchg_label_dst);
}

static void taint_cb_MUL_DIV(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
#define cb3_debug "taint_cb_MUL_DIV"

    DEBUG_OUTPUT(arg,cb3_debug);

    dfsan_label l1 = (arg->src.type==IMMEDIATE || arg->src.type==UNASSIGNED)? CONST_LABEL: get_taint(arg->src); //could be IMM
    dfsan_label l2 = get_taint(arg->src2); //eax

    dfsan_label l3 = get_taint(arg->src3); //edx

    if(arg->dst.size==1){
        if(l1==CONST_LABEL && l2==CONST_LABEL){ //no propagation
            return;
        }
        else{
            dfsan_label l4 =  dfsan_union(l1, l2, arg->operation, arg->dst.size,
                                          arg->src.addr.vaddr, arg->src2.addr.vaddr, arg->src.type, arg->src2.type, arg->dst.addr.vaddr, arg->dst.type);
            set_taint(arg->dst,l4); // eax
            set_flags(arg->flags,l4);
        }
    }
    else{ //rdx will be also tainted
        if(l1==CONST_LABEL && l2==CONST_LABEL && l3==CONST_LABEL){ //no propagation
            return;
        }
        else{
            dfsan_label l4 = dfsan_union(l2, l3, UNION_MULTIPLE_OPS , arg->src2.size,
                                         arg->src2.addr.vaddr, arg->src3.addr.vaddr, arg->src2.type, arg->src3.type, 0, MULTIPLE_OPS); //we need the union regardless because even the constants are needed

            dfsan_label l5 =  dfsan_union(l1, l4, arg->operation, arg->dst.size,
                                          arg->src.addr.vaddr, 0, arg->src.type, MULTIPLE_OPS, arg->dst.addr.vaddr, arg->dst.type); //EAX part; EAX and EDX would be affected as destination

            dfsan_label l6 = dfsan_union(l1, l4, arg->operation, arg->src3.size,
                                          arg->src.addr.vaddr, 0, arg->src.type, MULTIPLE_OPS, arg->src3.addr.id, arg->src3.type); //EDX part

            set_taint(arg->dst,l5); // eax part of mul/div

            set_taint(arg->src3,l6); // edx part of mul/div

            set_flags(arg->flags,l5);
        }
    }

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
        dfsan_label flags_shadow = get_taint(arg->src2);
        OUTPUT_ERROR(flags_shadow!=0,arg,"JUMP *** flags are tainted ***"); //in fact, this is where we should flip a branch
    }
}

static void taint_cb_CALL(unsigned int cpu_index, void *udata) {
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_CALL");

    int temp = arg->dst.addr.id;

    dfsan_label l1 = get_taint(arg->src2); //eip

    READ_VALUE(arg->dst, &arg->dst.addr.vaddr); //we need the value of stack register, we use the value as a memory address to store the eip taint
    arg->dst.type = MEMORY_IMPLICIT;
    set_taint(arg->dst,l1);

    arg->dst.addr.vaddr = temp;
    arg->dst.type = GLOBAL_IMPLICIT; //restore for the next cb call

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

    int temp = arg->src.addr.id;

    READ_VALUE(arg->src, &arg->src.addr.vaddr);
    arg->src.type = MEMORY_IMPLICIT;
    dfsan_label l1 = get_taint(arg->src); //esp

    arg->src.addr.vaddr = temp;
    arg->src.type = GLOBAL_IMPLICIT; //restore for the next cb call

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