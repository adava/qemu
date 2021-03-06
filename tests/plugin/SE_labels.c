/*
 * Copyright (C) 2019, Alex Bennée <alex.bennee@linaro.org>
 *
 * How vectorised is this code?
 *
 * Attempt to measure the amount of vectorisation that has been done
 * on some code by counting classes of instruction.
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */

// run by: ./x86_64-linux-user/qemu-x86_64 -d plugin -D ./SE_shadow.log -plugin tests/plugin/libSE_labels.so,arg=union_labels.txt,arg=file_graph.vz [path to binary like ./a.out]

#include <inttypes.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <glib.h>
#include <qemu-plugin.h>
#include <capstone.h>
#include <keystone/keystone.h>
#include <stdint.h>
//#include "lib/shadow_memory.h"
#include "lib/SE/label_propagation.c"

#include "lib/SE/asm_generation.c"

#define print_arg(name,src) printf("%s => id=%lu, type=%d\n",name,src.addr.vaddr, src.type)

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define ALLOC_SET0(ptr,type) ptr = malloc(sizeof(type)); \
                             memset(ptr,0,sizeof(type));

#define PLUGIN_OPT

#define LOG_ASSEMBLY


//static bool plugin_optimize=true;

static char *label_file=NULL;
static char *graph_file=NULL;
static char *asm_file=NULL;
//static char *asm_file="program_asm.txt";
static bool verbose;
GHashTable *unsupported_ins_log;
GHashTable *syscall_rets;
static uint32_t invocation_counter;

static dfsan_settings config = {.readFunc=&plugin_mem_read, .regValue=&plugin_reg_read, .printInst=&print_X86_instruction};

static inline void analyzeOp(shad_inq *inq, cs_x86_op operand){
    switch(operand.type){
        case X86_OP_REG:
            inq->type = GLOBAL;
            inq->addr.id = MAP_X86_REGISTER(operand.reg);
            break;
        case X86_OP_IMM:
            inq->type = IMMEDIATE;
            inq->addr.vaddr = operand.imm;
            break;
        case X86_OP_MEM:
            inq->type = MEMORY;
            break;
        default:
            printf("unsupported operand type=%d\n",operand.type);
            assert(0);
    }
    if(inq->addr.vaddr>=GLOBAL_POOL_SIZE && inq->type==GLOBAL){
        printf("operand.reg=%x name=%s, mapped_val=%x\n",operand.reg,get_reg_name(operand.reg),inq->addr.id);
        assert(0);
    }
    inq->size = operand.size<SHD_SIZE_MAX?operand.size:SHD_SIZE_u64;
}

static inline inst_callback_argument *analyze_Operands(cs_x86_op *operands,int numOps){
    inst_callback_argument *res = malloc(sizeof(inst_callback_argument));
    memset(res,0,sizeof(inst_callback_argument));
    switch(numOps){
        case 0:
            break;
        case 1:
            analyzeOp(&res->src, operands[0]);;
            break;
        case 2:
            analyzeOp(&res->src, operands[0]);
            analyzeOp(&res->dst, operands[1]);
            break;
        case 3:
            analyzeOp(&res->src, operands[0]);
            analyzeOp(&res->src2, operands[1]);
            analyzeOp(&res->dst, operands[2]);
            break;
        default:
            printf("WARNING: more than three operands=%d\n",numOps);
            break;
    }
    return res;
}

static inline void analyze_mem_Addr(inst_callback_argument *res, x86_op_mem *mem_op){ //assumes segment would not be tainted
    if (mem_op->index!=X86_REG_INVALID){
        res->src.addr.id = MAP_X86_REGISTER(mem_op->index);
        res->src.size = regsize_map_64[mem_op->index];
        res->src.type = GLOBAL;

    }else{
        res->src.type = UNASSIGNED;
        res->src.addr.id = -1; //invalid for Qemu regs
    }
    if (mem_op->base!=X86_REG_INVALID){
        res->src2.addr.id = MAP_X86_REGISTER(mem_op->base);
        res->src2.size = regsize_map_64[mem_op->base];
        res->src2.type = GLOBAL;
    }else{
        res->src2.type = UNASSIGNED;
        res->src2.addr.id = -1 ;
    }

    res->src3.addr.vaddr = mem_op->scale;
    res->src3.type = IMMEDIATE;
    res->src3.size = SHD_SIZE_u32;

    res->src4.addr.vaddr = mem_op->disp;
    res->src4.type = IMMEDIATE;
    res->src4.size = SHD_SIZE_u32;

}

static void op_mem(unsigned int cpu_index, qemu_plugin_meminfo_t meminfo,
                     uint64_t vaddr, void *udata)
{
    mem_callback_argument *arg;
    if (udata!=NULL){
        arg = (mem_callback_argument *)udata;
        *(arg->addr) = vaddr;
        DEBUG_MEMCB_OUTPUT(arg->addr);
#ifdef CONFIG_2nd_CCACHE
        shad_inq inq = {.addr.vaddr=vaddr,.type=MEMORY,.size=SHD_SIZE_u64};
        dfsan_label label=get_taint(inq);
        if(label && second_ccache_flag==CHECK){
#ifdef CONFIG_DEBUG_CCACHE_SWITCH
            printf("switching in op_mem\n");
#endif
            switch_mode(TRACK, true, arg->ip);
        }
#endif
        if (arg->args!=NULL && arg->callback!=NULL){
            arg->callback(cpu_index, (void *)arg->args);
        }
    }
    else{
        assert(0);
    }
}

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    g_autofree gchar *report = g_strdup_printf("\nDEBUG output end:\n");
    qemu_plugin_outs(report);

    int root = dfsan_fini(label_file, graph_file);

    dfsan_graphviz(root,graph_file);
    generate_asm_body(root);
    if(asm_file!=NULL){
        print_asm_slice_function(asm_file);
    }
    g_autoptr(GString) end_rep = g_string_new("\n");
    print_unsupported_ins(end_rep,unsupported_ins_log);
    g_string_append_printf(end_rep, "Done\n");
    qemu_plugin_outs(end_rep->str);
}

static void plugin_init(void)
{
//    printf("Register numbers=%d\n",X86_REG_ENDING);
    g_autoptr(GString) report = g_string_new("Initialization:\n");
#ifdef CONFIG_2nd_CCACHE
    printf("2nd code cache optimization is activated!\n");
#ifndef CONFIG_DEBUG_CCACHE_SWITCH
printf("debugging information for 2nd code cache optimization would not be printed!\n");
#endif
#endif
    unsupported_ins_log =  g_hash_table_new_full(NULL, g_direct_equal, NULL, NULL);
    syscall_rets =  g_hash_table_new_full(NULL, g_direct_equal, NULL, NULL);

    init_asm_generation(8);
    init_register_mapping();
    dfsan_init(&config);
    printInst = &print_X86_instruction;
    invocation_counter = 0;
#ifdef CONFIG_2nd_CCACHE
    second_ccache_flag = CHECK;
#endif
    g_string_append_printf(report,"Done!\n");
    qemu_plugin_outs(report->str);

}

static void syscall_callback(qemu_plugin_id_t id, unsigned int vcpu_index,
                                 int64_t num, uint64_t a1, uint64_t a2,
                                 uint64_t a3, uint64_t a4, uint64_t a5,
                                 uint64_t a6, uint64_t a7, uint64_t a8)
{
    g_autoptr(GString) out = g_string_new("******system call*******");
    g_string_append_printf(out,"\tnum: %"PRIu64"\n", num);
    // For read system call, num==0, a2 holds the buffer address (to which the read bytes are written) and a3 holds the buff size.
    if(num==0 && a1==0){ //only standard in; a1==0
//        uint8_t value = 0xff;
//        SHD_write_contiguous(a2, a3,value);

        uint64_t *vaddr = g_new0(uint64_t,1);
        *vaddr = a2;
        g_hash_table_insert(syscall_rets,(gpointer)(num),vaddr);
        g_string_append_printf(out,"TAINTED SOURCE\t I/O descriptor: %" PRIu64" , source addr: 0x%lx , buf size: %" PRIu64 "\n",
                a1,a2,a3);
        if(!DEBUG_SYSCALL){
            qemu_plugin_outs(out->str);
        }
    }
    if(DEBUG_SYSCALL){
        qemu_plugin_outs(out->str);
    }
}


static void syscall_ret_callback(qemu_plugin_id_t id, unsigned int vcpu_idx, int64_t num, int64_t ret){
    if(num==0){
        g_autoptr(GString) out = g_string_new("******system call return *******");
        g_string_append_printf(out,"\tTainting syscall num: %"PRIu64, num);
        uint64_t *addr = g_hash_table_lookup(syscall_rets, (gpointer)num);
        if(addr!=NULL){
            //create a label per byte
            mark_input_bytes((void *)*addr, ret, invocation_counter);
            invocation_counter+=ret;
            int removed = g_hash_table_remove(syscall_rets, (gpointer)num);
            g_assert(removed);
            g_string_append_printf(out,"\t addr=0x%"PRIx64"\tret=%"PRIu64" is done.\n",*addr,ret);
            qemu_plugin_outs(out->str);
#ifdef CONFIG_2nd_CCACHE
            if(second_ccache_flag!=TRACK){
                switch_mode(TRACK,false, 0);
            }
#endif
        }
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n = qemu_plugin_tb_n_insns(tb);
    tb_ip *tbIp;
    ALLOC_SET0(tbIp,tb_ip);

    size_t i;
    tb_num++;
    for (i = 0; i < n; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        mem_callback_argument *mem_cb_arg = NULL;
        void *usr_data=NULL;
        CB_TYPE cbType=BEFORE; //After is too late for Symbolic Execution because the recorded concrete value for cases where destination and source are the same would be wrong
        inst_callback_argument *cb_args=NULL;
        cs_insn *cs_ptr = (cs_insn*)cap_plugin_insn_disas(insn);

#ifdef LOG_ASSEMBLY
        char *ins_str = qemu_plugin_insn_disas(insn);
        g_autofree gchar *temp_gstr = g_strdup_printf("%s\n",ins_str);
        qemu_plugin_outs(temp_gstr);
#endif

        cs_x86 *inst_det = &cs_ptr->detail->x86;

        qemu_plugin_vcpu_udata_cb_t cb=NULL;

        cb_args = analyze_Operands(inst_det->operands,inst_det->op_count);
        cb_args->operation = cs_ptr->id; //sina: record the instruction ID as it appears
        assert(cs_ptr->id!=0);

#if 0 //testing implicit registers
        int rr=cs_ptr->detail->regs_read_count;
        int wr=cs_ptr->detail->regs_write_count;
        for(int i=0;i<rr;i++){
            const char *temp1=get_reg_name(cs_ptr->detail->regs_read[i]);
            if(cs_ptr->detail->regs_read[i]!=X86_REG_EFLAGS && cs_ptr->detail->regs_read[i]!=X86_REG_RSP){
                printf("inst=%s\tread_reg_name=%s\n",get_inst_name(cs_ptr->id),temp1);
            }
        }
        for(int i=0;i<wr;i++){
            const char *temp1=get_reg_name(cs_ptr->detail->regs_write[i]);
            if(cs_ptr->detail->regs_write[i]!=X86_REG_EFLAGS && cs_ptr->detail->regs_write[i]!=X86_REG_RSP){
                printf("inst=%s\twrite_reg_name=%s\n",get_inst_name(cs_ptr->id),temp1);
            }
        }
#endif

#ifdef CONFIG_2nd_CCACHE
        if (i==0){
            tbIp->ip=qemu_plugin_insn_vaddr(insn);
//                if(tbIp->ip==0x402930){
//                    char *is=qemu_plugin_insn_disas(insn);
//                    printf("inst at ip=%lx is %s\n",tbIp->ip,is);
//                }
        }
#endif
        switch(cs_ptr->id){
            case X86_INS_MOVABS:
            case X86_INS_MOVZX:
            case X86_INS_MOVSX:
            case X86_INS_MOVSXD: //Using Max of src and dst size in taint_cb_2ops handles these operations
                //these instructions should execute but don't depend on flags
                if(cb_args->src.size!=cb_args->dst.size){ //otherwise, they act similar to move
                    cb_args->src2.type = UNASSIGNED;
                    cb_args->src2.addr.id = 0;
                    cb = taint_cb_2ops;
                    break;
                }
            case X86_INS_MOV:
                //better to take this outside, and set it to NULL for otherwise case
                cb_args->src.type==IMMEDIATE?(cb = taint_cb_clear_all):(cb = taint_cb_mov);
                break;
            case X86_INS_CMOVA: //CMOVcc family does not affect flags
            case X86_INS_CMOVAE:
            case X86_INS_CMOVB:
            case X86_INS_CMOVBE:
            case X86_INS_CMOVE:
            case X86_INS_CMOVG:
            case X86_INS_CMOVGE:
            case X86_INS_CMOVL:
            case X86_INS_CMOVLE:
            case X86_INS_CMOVNE:
            case X86_INS_CMOVNO:
            case X86_INS_CMOVNP:
            case X86_INS_CMOVNS:
            case X86_INS_CMOVO:
            case X86_INS_CMOVP:
            case X86_INS_CMOVS:
            case X86_INS_MOVD:  /* MOVD can also be used for XMM but rn only r/m32, mm and reverse would work */
            /* the above should propagate conditionally. The src is never imm for them so the check below never applies */
                cb_args->src2.type = GLOBAL_IMPLICIT;
                cb_args->src2.addr.id = FLAG_REG;
                cb = taint_cb_2ops;
                break;
            case X86_INS_SHR: //all arithmetics are similar
            case X86_INS_SAR:
            case X86_INS_SHL:
            case X86_INS_SAL:
            case X86_INS_AND:
            case X86_INS_OR:
            case X86_INS_ROR:
            case X86_INS_XOR:
            case X86_INS_SUB:
            case X86_INS_ADD:
                copy_inq(cb_args->dst, cb_args->src2);
                cb_args->dst.type = (enum shadow_type)((uint8_t)(cb_args->dst.type)+1); //convert the type to implicit
                cb_args->flags.addr.id=FLAG_REG;
                cb_args->flags.type=GLOBAL;
                cb = taint_cb_2ops;
                break;
            case X86_INS_CMP:
            case X86_INS_TEST:
            copy_inq(cb_args->dst,cb_args->src2);
                cb_args->dst.type = GLOBAL_IMPLICIT;
                cb_args->dst.addr.id = FLAG_REG;
                cb = taint_cb_2ops;
                break;
            case X86_INS_NEG:
            case X86_INS_INC:
            case X86_INS_DEC:
                cb_args->src2.type = 0;
                cb_args->src2.addr.id = UNASSIGNED;
                copy_inq(cb_args->src,cb_args->dst);
                cb_args->dst.type = (enum shadow_type)((uint8_t)(cb_args->dst.type)+1);
                cb_args->flags.addr.id=FLAG_REG;
                cb_args->flags.type=GLOBAL;
                cb = taint_cb_2ops;
                break;
            case X86_INS_NOT:
                cb_args->src2.type = 0;
                cb_args->src2.addr.id = UNASSIGNED;
                copy_inq(cb_args->src,cb_args->dst);
                cb_args->dst.type = (enum shadow_type)((uint8_t)(cb_args->dst.type)+1);
                cb = taint_cb_2ops;
                break;
            case X86_INS_BSF:
            case X86_INS_BSR:
                cb_args->flags.addr.id=FLAG_REG;
                cb_args->flags.type=GLOBAL;
                cb = taint_cb_2ops;
                break;
            case X86_INS_BT:
            case X86_INS_BTC:
            case X86_INS_BTR:
            case X86_INS_BTS:
                //only propagate conservatively to the flags
                cb_args->dst.type = GLOBAL_IMPLICIT;
                cb_args->dst.addr.id = FLAG_REG;
                cb = taint_cb_mov;
                break;
            case X86_INS_PUSH:
                cb_args->dst.type = MEMORY_IMPLICIT;
                cb_args->dst.size = cb_args->src.size;
                cb = cb_args->src.type==IMMEDIATE?taint_cb_clear_all:taint_cb_mov;
                break;
            case X86_INS_POP:
                copy_inq(cb_args->src,cb_args->dst);
                cb_args->src.type = MEMORY_IMPLICIT;
                cb_args->src.addr.vaddr = 0;
                cb_args->src.type==IMMEDIATE?(cb = taint_cb_clear_all):(cb = taint_cb_mov);
                break;
              /*dst = LEFT(UNION(src1,SHIFT(src2,sh_val)))*/
            case X86_INS_ADC:
            case X86_INS_SBB:
                copy_inq(cb_args->dst, cb_args->src3); //to be consistent with FP instructions
                cb_args->src2.type = GLOBAL_IMPLICIT;
                cb_args->src2.addr.id = FLAG_REG;
                cb_args->dst.type = (enum shadow_type)((uint8_t)(cb_args->dst.type)+1); //convert the type to implicit
                cb_args->flags.addr.id=FLAG_REG;
                cb_args->flags.type=GLOBAL;
                cb = taint_cb_3ops;
                break;
            case X86_INS_CWD: //propagate from AX to DX
            case X86_INS_CDQ: //propagate from EAX to EDX
            case X86_INS_CQO: //another alias is cqto, propagates from RAX to RDX
            case X86_INS_CBW: //propagates from AL to AH but we track the entire RAX
            case X86_INS_CWDE:
            case X86_INS_CDQE: //cltq, propagates from EAX to RAX but we track the entire RAX
                // we track the entire RAX
                memset(cb_args,0,sizeof(inst_callback_argument));
                cb_args->operation = cs_ptr->id;
                cb_args->src.type = GLOBAL_IMPLICIT;
                cb_args->src.addr.id = R_EAX;
                switch (cs_ptr->id){
                    case X86_INS_CBW:
                        cb_args->src.size = SHD_SIZE_u8;
                        cb_args->dst.addr.id = R_EAX;
                        break;
                    case X86_INS_CWDE:
                        cb_args->src.size = SHD_SIZE_u16;
                        cb_args->dst.addr.id = R_EAX;
                        break;
                    case X86_INS_CDQE:
                        cb_args->src.size = SHD_SIZE_u32;
                        cb_args->dst.addr.id = R_EAX;
                        break;
                    case X86_INS_CWD:
                        cb_args->src.size = SHD_SIZE_u16;
                        cb_args->dst.addr.id = R_EDX;
                        break;
                    case X86_INS_CDQ:
                        cb_args->src.size = SHD_SIZE_u32;
                        cb_args->dst.addr.id = R_EDX;
                        break;
                    case X86_INS_CQO:
                        cb_args->src.size = SHD_SIZE_u64;
                        cb_args->dst.addr.id = R_EDX;
                        break;
                    default:
                        break;
                }
                cb_args->src2.type = 0;
                cb_args->src2.addr.id = UNASSIGNED;

                cb_args->dst.type = GLOBAL_IMPLICIT;

                cb = taint_cb_2ops;
                break;
            case X86_INS_XCHG:
                cb = taint_cb_XCHG;
                break;
            case X86_INS_CMPXCHG:
                cb_args->src2.addr.id=MAP_X86_REGISTER(X86_REG_RAX);
                cb_args->src2.type=GLOBAL_IMPLICIT;
                cb_args->flags.addr.id=FLAG_REG;
                cb_args->flags.type=GLOBAL;
                cb = taint_cb_CMPCHG;
                break;
            case X86_INS_IMUL:
            case X86_INS_IDIV:
                if (inst_det->op_count==2){
                    copy_inq(cb_args->dst, cb_args->src2);
                    cb_args->dst.type = GLOBAL_IMPLICIT;
                    cb_args->flags.addr.id=FLAG_REG;
                    cb_args->flags.type=GLOBAL;
                    cb = taint_cb_2ops;
                    break;
                }
                else if (inst_det->op_count==3){ //src is immediate
                    cb = taint_cb_2ops;
                    cb_args->flags.addr.id=FLAG_REG;
                    cb_args->flags.type=GLOBAL;
//                    print_ops(cs_ptr->mnemonic, cs_ptr->op_str);
                    break;
                }
                //IDIV/IDIV with 1 op is similar to Mul/Div
            case X86_INS_MUL:
            case X86_INS_DIV:
                cb_args->src2.type = GLOBAL_IMPLICIT;
                cb_args->src2.addr.id = MAP_X86_REGISTER(X86_REG_RAX);
                cb_args->src2.size = cb_args->src.size;
                cb_args->src3.type = GLOBAL_IMPLICIT;
                cb_args->src3.addr.id = MAP_X86_REGISTER(X86_REG_RDX);
                cb_args->src3.size = cb_args->src.size;
                cb_args->dst.type = GLOBAL_IMPLICIT;
                cb_args->dst.addr.id = MAP_X86_REGISTER(X86_REG_RAX);
                cb_args->dst.size = cb_args->src.size;

                cb_args->flags.addr.id=FLAG_REG;
                cb_args->flags.type=GLOBAL;

                cb = taint_cb_MUL_DIV;
                break;
            case X86_INS_LEA:
                analyze_mem_Addr(cb_args,&inst_det->operands[0].mem);
                cb = taint_cb_effmem;
                break;
            case X86_INS_SYSCALL: //tainting input is handled in system call cb
                memset(cb_args,0,sizeof(inst_callback_argument));
                cb_args->operation = X86_INS_SYSCALL;
                cb_args->src.addr.id=MAP_X86_REGISTER(X86_REG_RCX);
                cb_args->src.type=GLOBAL_IMPLICIT;
                cb_args->src.size=SHD_SIZE_u64;

                cb_args->dst.addr.id=MAP_X86_REGISTER(X86_REG_RSP); //propagate from RCX to RSP
                cb_args->dst.type=GLOBAL_IMPLICIT;
                cb_args->dst.size=SHD_SIZE_u64;

                cb_args->src2.addr.id=MAP_X86_REGISTER(X86_REG_RDX);
                cb_args->src2.type=GLOBAL_IMPLICIT;
                cb_args->src2.size=SHD_SIZE_u64;

                cb_args->src3.addr.id=MAP_X86_REGISTER(X86_REG_RIP); //propagate from RDX to RSP
                cb_args->src3.type=GLOBAL_IMPLICIT;
                cb_args->src3.size=SHD_SIZE_u64;

                cb = taint_cb_mov2;
                break;
            case X86_INS_CALL:
                cb_args->src2.addr.id = R_EIP;
                cb_args->src2.type = GLOBAL_IMPLICIT; //IMPLICIT mentioning doesn't matter as long as there is not union (instruction recording) but I do it anyway
                cb_args->src2.size = SHD_SIZE_u64;
                cb_args->dst.addr.id = R_ESP;
                cb_args->dst.type = GLOBAL_IMPLICIT;
                cb_args->dst.size = SHD_SIZE_u64;
                cbType = BEFORE;
                cb = taint_cb_CALL;
                break;
            case X86_INS_RET:
                cb_args = malloc(sizeof(inst_callback_argument));
                cb_args->src.addr.id = R_ESP;
                cb_args->src.type = GLOBAL_IMPLICIT;
                cb_args->src.size = SHD_SIZE_u64;
                cb_args->dst.addr.id = R_EIP;
                cb_args->dst.type = GLOBAL_IMPLICIT;
                cb_args->dst.size = SHD_SIZE_u64;
                cb = taint_cb_RET;
                cbType = BEFORE;
                break;
            case X86_INS_LEAVE:
                memset(cb_args,0,sizeof(inst_callback_argument));
                cb_args->operation = X86_INS_LEAVE;
                cb_args->src.type = MEMORY_IMPLICIT;
                cb_args->src.size = SHD_SIZE_u64;

                cb_args->src2.addr.id=MAP_X86_REGISTER(X86_REG_RBP);
                cb_args->src2.type=GLOBAL_IMPLICIT;
                cb_args->src2.size=SHD_SIZE_u64;

                cb_args->dst.addr.id=MAP_X86_REGISTER(X86_REG_RSP);
                cb_args->dst.type=GLOBAL_IMPLICIT;
                cb_args->dst.size=SHD_SIZE_u64;

                cb = taint_cb_LEAVE;
                break;
            case X86_INS_JAE:
            case X86_INS_JA:
            case X86_INS_JBE:
            case X86_INS_JB:
            case X86_INS_JCXZ:
            case X86_INS_JECXZ:
            case X86_INS_JE:
            case X86_INS_JGE:
            case X86_INS_JG:
            case X86_INS_JLE:
            case X86_INS_JL:
            case X86_INS_JNE:
            case X86_INS_JNO:
            case X86_INS_JNP:
            case X86_INS_JNS:
            case X86_INS_JO:
            case X86_INS_JP:
            case X86_INS_JS:
                cb_args->operation = COND_JMP;
                cb_args->src2.addr.id = FLAG_REG;
                cb_args->src2.type = GLOBAL;
//            case X86_INS_JRCXZ: special instruction, checks registers instead of flags
            case X86_INS_JMP:
                cb = taint_cb_JUMP; //no propagation, just checking whether the branch condition is tainted
                cbType = cb_args->src.type==MEMORY?INMEM:BEFORE;
                break;
            case X86_INS_CPUID:
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb_args->src.addr.id=MAP_X86_REGISTER(X86_REG_RAX);
                cb_args->src.type=GLOBAL_IMPLICIT;
                cb_args->src.size=SHD_SIZE_u64;

                cb_args->src2.addr.id=MAP_X86_REGISTER(X86_REG_RBX);
                cb_args->src2.type=GLOBAL_IMPLICIT;
                cb_args->src2.size=SHD_SIZE_u64;

                cb_args->src3.addr.id=MAP_X86_REGISTER(X86_REG_RCX);
                cb_args->src3.type=GLOBAL_IMPLICIT;
                cb_args->src3.size=SHD_SIZE_u64;

                cb_args->dst.addr.id=MAP_X86_REGISTER(X86_REG_RDX);
                cb_args->dst.type=GLOBAL_IMPLICIT;
                cb_args->dst.size=SHD_SIZE_u64;

                cb = taint_cb_clear_all;
                break;
            case X86_INS_RDTSC:
                //print_ops(cs_ptr->mnemonic, cs_ptr->op_str);
                ALLOC_SET0(cb_args,inst_callback_argument)
                cb_args->src.addr.id=MAP_X86_REGISTER(X86_REG_RAX);
                cb_args->src.type=GLOBAL_IMPLICIT;
                cb_args->src.size=SHD_SIZE_u64;

                cb_args->src2.addr.id=MAP_X86_REGISTER(X86_REG_RDX);
                cb_args->src2.type=GLOBAL_IMPLICIT;
                cb_args->src2.size=SHD_SIZE_u64;

                cb = taint_cb_clear_all;
                break;
            case X86_INS_SETAE:
            case X86_INS_SETA:
            case X86_INS_SETBE:
            case X86_INS_SETB:
            case X86_INS_SETE:
            case X86_INS_SETGE:
            case X86_INS_SETG:
            case X86_INS_SETLE:
            case X86_INS_SETL:
            case X86_INS_SETNE:
            case X86_INS_SETNO:
            case X86_INS_SETNP:
            case X86_INS_SETNS:
            case X86_INS_SETO:
            case X86_INS_SETP:
            case X86_INS_SETS:
                copy_inq(cb_args->src,cb_args->dst);
                cb_args->src.addr.id = FLAG_REG;
                cb_args->src.type = GLOBAL_IMPLICIT;
                cb_args->src2.addr.id = 0;
                cb_args->src2.type = UNASSIGNED;
                cb = taint_cb_2ops;
                break;
            case X86_INS_STOSB:
            case X86_INS_STOSW:
            case X86_INS_STOSD:
            case X86_INS_STOSQ:
                //we should compute the effective address
                copy_inq(cb_args->src,cb_args->dst);
                cb_args->src.addr.id=MAP_X86_REGISTER(X86_REG_RAX);
                cb_args->src.type=GLOBAL_IMPLICIT;
//                cb_args->src.size=cb_args->dst.size; already set to that
                cb = taint_cb_mov;
                cbType = INMEM; //the problem is that inserting the cb after the instruction is too late (never hit), and before is too soon; we don't have the address.
                break;
            case X86_INS_NOP:
                free(cb_args);
                cb_args = NULL;
                break;
            default:
                if(inst_det->op_count==2){ // a majority of SSE instructions are handled here
                    copy_inq(cb_args->dst, cb_args->src2);
                    cb_args->dst.type = (enum shadow_type)((uint8_t)(cb_args->dst.type)+1); //convert the destination type to implicit
                    cb = taint_cb_2ops;
                }
                else if(inst_det->op_count==3){ //very conservative as we assume all three operands would affect the taint of the destination assumed to be the first operand
                    copy_inq(cb_args->dst, cb_args->src3);
                    cb_args->dst.type = (enum shadow_type)((uint8_t)(cb_args->dst.type)+1); //convert the type to implicit
                    cb = taint_cb_3ops;
                }
                else{
                    free(cb_args);
                    cb_args = NULL;
                    handle_unsopported_ins(cs_ptr, unsupported_ins_log);
                }
                break;
        }
        //register memory callback to get the vaddr if one of the operands is mem (only one operand address would be retrieved that is consistent with x86)
//#define cmp_src_dst_size(ssize,dsize,op) if(ssize!=dsize){printf("mem_size=%d, dst_size=%d, op=%s\n",ssize,dsize,get_inst_name(op));}
        if (cb_args!=NULL){
            //usr_data should be allocated
//            assert(cb_args->operation!=0);
            usr_data = (void*)cb_args;
            if (cb_args->src.type == MEMORY || cb_args->src.type == MEMORY_IMPLICIT){ //for instance Pop
                ALLOC_SET0(mem_cb_arg,mem_callback_argument)
                mem_cb_arg->addr = &(cb_args->src.addr.vaddr);
            }
            else if (cb_args->src2.type == MEMORY){ //for instance in CMP or ADC, src shouldn't be MEMORY_IMPLICIT
                ALLOC_SET0(mem_cb_arg,mem_callback_argument)
                mem_cb_arg->addr = &(cb_args->src2.addr.vaddr);

            }
            else if (cb_args->src3.type == MEMORY){ //for instance FP with 3 ops, src3 shouldn't be MEMORY_IMPLICIT
                ALLOC_SET0(mem_cb_arg,mem_callback_argument)
                mem_cb_arg->addr = &(cb_args->src3.addr.vaddr);


            }
            else if (cb_args->dst.type == MEMORY  || cb_args->dst.type == MEMORY_IMPLICIT){ //for instance Push
                ALLOC_SET0(mem_cb_arg,mem_callback_argument)
                mem_cb_arg->addr = &(cb_args->dst.addr.vaddr);

            }

        }
        if (mem_cb_arg!=NULL){
            qemu_plugin_register_vcpu_mem_cb(insn, op_mem,
                                             QEMU_PLUGIN_CB_NO_REGS,
                                             QEMU_PLUGIN_MEM_RW, (void *)mem_cb_arg);
            mem_cb_arg->ip = qemu_plugin_insn_vaddr(insn);
            cbType = INMEM;
        }
        //register the selected callback
        if(cb!=NULL && usr_data!=NULL
#ifdef CONFIG_2nd_CCACHE
                                    && second_ccache_flag
#endif
                                    ){
            nice_print(cs_ptr);
            switch(cbType){
                case AFTER:
                    qemu_plugin_register_vcpu_after_insn_exec_cb(
                            insn, cb , QEMU_PLUGIN_CB_NO_REGS, usr_data);
                    break;
                case BEFORE:
                    qemu_plugin_register_vcpu_insn_exec_cb(
                            insn, cb , QEMU_PLUGIN_CB_NO_REGS, usr_data);
                    break;
                case INMEM:
                    mem_cb_arg->args = cb_args;
                    mem_cb_arg->callback = cb;
                    break;
                default:
                    printf("this callback type is not supported!\n");
                    assert(0);
            }
        }
//        if (i==n-1){
//            tb_ip *tbIp;
//            ALLOC_SET0(tbIp,tb_ip);
//            tbIp->ip=qemu_plugin_insn_vaddr(insn);
//            tbIp->tb = tb_num;
//            qemu_plugin_register_vcpu_insn_exec_cb(insn, vcpu_tb_exec,
//                                                         QEMU_PLUGIN_CB_NO_REGS,
//                                                         (void *)tbIp);
//        }
    }
#ifdef CONFIG_2nd_CCACHE
    qemu_plugin_register_vcpu_tb_exec_cb(tb, vcpu_tb_exec, QEMU_PLUGIN_CB_NO_REGS, (void *)tbIp);
#endif

}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    int i;

    for (i = 0; i < argc; i++) {
        char *p = argv[i];
        if (i == 0) {
            label_file = strdup(p);
        }
        else if (i == 1) {
            graph_file = strdup(p);
        }
        else if (i == 2) {
            asm_file = strdup(p);
        }
        else if (strcmp(p, "verbose") == 0) {
            verbose = true;
        }
    }

    plugin_init();
//    printf("here\n");
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);
    qemu_plugin_register_vcpu_syscall_cb(id, syscall_callback);
    qemu_plugin_register_vcpu_syscall_ret_cb(id, syscall_ret_callback);
    return 0;
}
