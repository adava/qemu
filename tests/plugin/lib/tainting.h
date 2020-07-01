//
// Created by sina on 4/27/20.
//
#include <stdint.h>
#define GLOBAL_POOL_SIZE X86_REG_ENDING + 20
#include "taint_propagation.h"
#include "lib/utility.c"
#ifndef TAINTING_H
#define TAINTING_H

typedef struct{
    uint64_t src_val;
    uint64_t dst_val;
    uint64_t src2_val;
} inst_callback_values;

typedef struct{
    shad_inq src;
    shad_inq dst;
    instruction_operation operation;
    shad_inq src2;
    shad_inq src3; //When effective address calculation is needed e.g. LEA
    inst_callback_values *vals;
} inst_callback_argument;

typedef struct{
    char *operand;
    uint64_t *addr;
    uint64_t ip;
    inst_callback_argument *args;
    qemu_plugin_vcpu_udata_cb_t callback;
} mem_callback_argument;

typedef enum {
    BEFORE,
    AFTER,
    INMEM
} CB_TYPE;

typedef struct{
    uint64_t ip;
    int tb;
} tb_ip;
int tb_num=0;
int tb_switched = -1;
#define READ_VALUE(inq,buf) switch(inq.type){ \
                                case GLOBAL:\
                                    plugin_reg_read(inq.addr.id,inq.size,buf);\
                                    break;\
                                case MEMORY:\
                                    plugin_mem_read(inq.addr.vaddr,inq.size,buf);\
                                    break;\
                                case IMMEDIATE:\
                                    *(uint64_t *)buf = inq.addr.vaddr; \
                                    break;\
                                default:\
                                    break;\
                            }


#ifdef DEBUG_CB
#define DEBUG_OUTPUT(arg, inst_s) g_autofree gchar *o1=g_strdup_printf("%s: src=0x%lx, size=%d, type=%d\t src2=0x%lx, size=%d, type=%d\t dst=0x%lx, size=%d, type=%d\n",inst_s,\
                                  arg->src.addr.vaddr, arg->src.size, arg->src.type,arg->src2.addr.vaddr, arg->src2.size, arg->src2.type,arg->dst.addr.vaddr, arg->dst.size, arg->dst.type);\
                                  qemu_plugin_outs(o1);

#define OUTPUT_ERROR(err, arg, inst_s)  if (err){\
g_autofree gchar *o2 = g_strdup_printf("SHADOW error in %s inst callback#\toperands: src=%lx, dst=%lx\n",inst_s, arg->src.addr.vaddr, arg->dst.addr.vaddr);\
qemu_plugin_outs(o2);}

#else
#define DEBUG_OUTPUT(arg, inst_s)
#define OUTPUT_ERROR(err, arg, inst_s) if (err){\
;}
#endif

#define INIT_ARG(arg,udata)  inst_callback_argument *arg;\
                             if (udata!=NULL){\
                                arg = (inst_callback_argument *)udata;\
                             } else{assert(0);}\

#ifdef DEBUG_MEMCB
#define DEBUG_MEMCB_OUTPUT(vaddr)  {\
                                    g_autofree gchar *o2 = g_strdup_printf("#op_mem callback#\tvaddr=%lx\n",*(uint64_t *)(vaddr));\
                                    qemu_plugin_outs(o2);}
#else
#define DEBUG_MEMCB_OUTPUT(vaddr)
#endif

#ifdef LOG_INS

#define nice_print(insn) print_id_groups(insn)

#else


static inline void nice_print(cs_insn *insn)
{
//    gchar *out;
//    GString *report;
    switch(insn->id) {
//        case X86_INS_CMP:
//        case X86_INS_CMPXCHG:
//            out = g_strdup_printf("num_operands: %d, op1=%" PRIu32 ", op2=%" PRIu32 "\n", insn->detail->x86.op_count, insn->detail->x86.operands[0].reg, insn->detail->x86.operands[1].reg);
//            qemu_plugin_outs(out);
//            break;
//        case X86_INS_LEA:
//            report = g_string_new("*X86_INS_LEA*\t");
//            print_mem_op(&insn->detail->x86.operands[0].mem, report);
//            qemu_plugin_outs(report->str);
//            break;
//        case X86_INS_CQO: //cqto
//        case X86_INS_CLTS:
//        case X86_INS_CWD:
//        case X86_INS_CWDE:
//        case X86_INS_CDQ:
//        case X86_INS_CDQE: //cltq
//        case X86_INS_STOSB:
//        case X86_INS_STOSW:
//        case X86_INS_STOSD:
//        case X86_INS_STOSQ:
//            print_id_groups(insn);
//            break;
        default:
            break;
    }

}



#endif

static inline void handle_unsopported_ins(cs_insn *cs_i, GHashTable *log){
    char *inst = NULL;

    char *instance = (char *)g_hash_table_lookup(log, GUINT_TO_POINTER(cs_i->id));
    if (!instance) {
        inst = strdup(cs_i->mnemonic);
        g_hash_table_insert(log, GUINT_TO_POINTER(cs_i->id),(gpointer)inst);
#ifdef LOG_INS
        print_ops(cs_i->mnemonic, cs_i->op_str);
        print_id_groups(cs_i);
#endif
    }
    //log(report,"0x%lx -> 0x%lx!\n",id,shadow);
}

static inline void print_unsupported_ins(GString *report_str,GHashTable *log){
    GList *ins = g_hash_table_get_values(log);
    if (ins && g_list_next(ins)) {
        while (g_list_next(ins)) {
            ins = g_list_next(ins);
            char *rec = (char *) ins->data;
            g_string_append_printf(report_str,
                                   "Unsupported Instr: %s\n",rec);
        }
        g_list_free(ins);
    }
}

#define set_opId(id,op) switch(id){\
                        case X86_INS_SHR:\
                            op = Shr;\
                            break;\
                        case X86_INS_SAR:\
                            op = Sar;\
                            break;\
                        case X86_INS_SHL:\
                            op = Shl;\
                            break;\
                        case X86_INS_SAL:\
                            op = Sal;\
                            break;\
                        case X86_INS_ROL:\
                            op = Rol;\
                            break;\
                        case X86_INS_ROR:\
                            op = Ror;\
                            break;\
                        case X86_INS_AND:\
                            op = OP_AND;\
                            break;\
                        case X86_INS_OR:\
                            op = OP_OR;\
                            break;\
                        default:\
                            assert(0);\
                        }

void taint_nbench_arginregs(uint64_t current_ip, uint64_t bb_addr, uint32_t addr_reg, uint32_t size_reg);
void taint_nbench_arginreg_fix(uint64_t current_ip,uint64_t bb_addr,uint32_t addr_reg, uint32_t mem_size);
void taint_nbench_str(uint64_t current_ip, uint64_t bb_addr);
void taint_nbench_array(uint64_t current_ip,uint64_t bb_addr,uint32_t array_stack_offset,uint32_t size_stack_offset);
void taint_nbench_fix(uint64_t current_ip,uint64_t bb_addr,uint32_t array_stack_offset, uint64_t mem_size);
void taint_nbench_stack(uint64_t current_ip,uint64_t bb_addr,uint32_t array_stack_offset, uint64_t mem_size);

static void taint_cb_mov(unsigned int cpu_index, void *udata);
static void taint_cb_clear(unsigned int cpu_index, void *udata);
static void taint_cb_ADD_SUB(unsigned int cpu_index, void *udata);
static void taint_cb_CMP(unsigned int cpu_index, void *udata);
static void taint_cb_XOR(unsigned int cpu_index, void *udata);
static void taint_cb_SR(unsigned int cpu_index, void *udata); //shift/rotate operations
static void taint_cb_EXTENDL(unsigned int cpu_index, void *udata);
static void taint_cb_XCHG(unsigned int cpu_index, void *udata);
static void taint_cb_AND_OR(unsigned int cpu_index, void *udata);
static void taint_cb_TEST(unsigned int cpu_index, void *udata);
static void taint_cb_MUL_DIV(unsigned int cpu_index, void *udata);
static void taint_cb_RET(unsigned int cpu_index, void *udata);
static void taint_cb_CALL(unsigned int cpu_index, void *udata);
static void taint_cb_JUMP(unsigned int cpu_index, void *udata);
static void taint_cb_CPUID(unsigned int cpu_index, void *udata);
static void taint_cb_RDTSC(unsigned int cpu_index, void *udata);
static void taint_cb_LEAVE(unsigned int cpu_index, void *udata);
static void taint_cb_movwf(unsigned int cpu_index, void *udata);
static void taint_cb_SETF(unsigned int cpu_index, void *udata);
static void taint_list_all(void);
GString *report;
#endif //QEMU_TAINTING_H
