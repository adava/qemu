//
// Created by sina on 4/27/20.
//
#include <stdint.h>
#define GLOBAL_POOL_SIZE X86_REG_ENDING + 20
#include "taint_propagation.h"
#ifndef TAINTING_H
#define TAINTING_H

#define INIT_ARG(arg,udata)  inst_callback_argument *arg;\
                             if (udata!=NULL){\
                                arg = (inst_callback_argument *)udata;\
                             } else{assert(0);}\

#define OUTPUT_ERROR(err, arg, inst_s)  if (err){\
                                    g_autofree gchar *o2 = g_strdup_printf("SHADOW error in %s inst callback#\toperands: src=%lu, dst=%lu\n",inst_s, arg->src.addr.vaddr, arg->dst.addr.vaddr);\
                                    qemu_plugin_outs(o2);}\

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

typedef struct{
    char *operand;
    uint64_t *addr;
} mem_callback_argument;

typedef struct{
    shad_inq src;
    shad_inq dst;
    instruction_operation operation;
} inst_callback_argument;

static void taint_cb_mov(unsigned int cpu_index, void *udata);
static void taint_cb_clear(unsigned int cpu_index, void *udata);
static void taint_cb_ADD_SUB(unsigned int cpu_index, void *udata);
static void taint_cb_XOR(unsigned int cpu_index, void *udata);
static void taint_cb_SR(unsigned int cpu_index, void *udata); //shift/rotate operations
static void taint_cb_EXTENDL(unsigned int cpu_index, void *udata);
static void taint_cb_XCHG(unsigned int cpu_index, void *udata);
static void taint_cb_AND_OR(unsigned int cpu_index, void *udata);
static void taint_cb_MUL_DIV(unsigned int cpu_index, void *udata);
#endif //QEMU_TAINTING_H
