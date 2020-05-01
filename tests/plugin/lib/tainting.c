//
// Created by sina on 4/28/20.
//
#include <stdlib.h>
#include <qemu-plugin.h>
#include "lib/tainting.h"
#include "lib/taint_propagation.c"
#include "lib/shadow_memory.c"

#define DEBUG_OUTPUT(arg, inst_s) g_autofree gchar *o1=g_strdup_printf("%s: src=%lx, size=%d, type=%d\t dst=%lx, size=%d, type=%d\n",inst_s,\
                                  arg->src.addr.vaddr, arg->src.size, arg->src.type,arg->dst.addr.vaddr, arg->dst.size, arg->dst.type);\
                                  qemu_plugin_outs(o1);

static void taint_cb_mov(unsigned int cpu_index, void *udata){ //use taint_cb prefix instead of SHD
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_mov");
    err = SHD_copy(arg->src,&arg->dst);
    OUTPUT_ERROR(err,arg,"MOV");
    free(udata);
}

static void taint_cb_clear(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    err = SHD_clear(&arg->dst);
    OUTPUT_ERROR(err,arg,"CLEAR");
    free(udata);
}

static void taint_cb_ADD_SUB(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_ADD_SUB");
    err = SHD_add_sub(arg->src,&arg->dst);
    //handle eflags
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"ADD/SUB");
    free(udata);
}

static void taint_cb_XOR(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_XOR");
    err = SHD_union(arg->src,&arg->dst);
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"XOR");
    free(udata);
}

static void taint_cb_SR(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_SR");
    err = SHD_Shift_Rotation(arg->src,&arg->dst,arg->operation);
    OUTPUT_ERROR(err,arg,"SHIFT/ROTATION");
    free(udata);
}

static void taint_cb_EXTENDL(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_EXTENDL");
    err = SHD_extensionL(arg->src,&arg->dst);
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"INC/DEC");
    free(udata);
}

static void taint_cb_XCHG(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_XCHG");
    err = SHD_exchange(&arg->src,&arg->dst);
    OUTPUT_ERROR(err,arg,"XCHG");
    free(udata);
}
#define READ_VALUE(inq,buf) switch(inq.type){ \
                                case GLOBAL:\
                                    plugin_reg_read(MAP_X86_REGISTER(inq.addr.id),inq.size,buf);\
                                    break;\
                                case MEMORY:\
                                    plugin_mem_read(inq.addr.vaddr,inq.size,buf);\
                                    break;\
                                case IMMEDIATE:\
                                    break;\
                                default:\
                                    assert(0);\
                            }
static void taint_cb_AND_OR(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_AND_OR");
    uint8_t buf_src_val[SHD_SIZE_MAX]={0};
    uint8_t buf_dst_val[SHD_SIZE_MAX]={0};
    READ_VALUE(arg->src,buf_src_val);
    READ_VALUE(arg->dst,buf_dst_val);
    err = SHD_and_or(arg->src,&arg->dst,buf_src_val,buf_dst_val,arg->operation);
    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);
    OUTPUT_ERROR(err,arg,"XCHG");
    free(udata);
}

static void taint_cb_MUL_DIV(unsigned int cpu_index, void *udata){
    shadow_err err = 0;
    INIT_ARG(arg,udata);
    DEBUG_OUTPUT(arg,"taint_cb_MUL_DIV");
    arg->dst.type = GLOBAL;
    switch(arg->src.size){
        case SHD_SIZE_u8:
            arg->dst.addr.id = X86_REG_AX;
            arg->dst.size = SHD_SIZE_u16;
            break;
        case SHD_SIZE_u16:
            arg->dst.addr.id =X86_REG_AX;
            arg->dst.size = SHD_SIZE_u16;
            err = SHD_copy_conservative(arg->src,&arg->dst);
            OUTPUT_ERROR(err,arg,"Mul");
            arg->dst.addr.id =X86_REG_DX;
            break;
        case SHD_SIZE_u32:
            arg->dst.addr.id =X86_REG_EAX;
            arg->dst.size = SHD_SIZE_u32;
            err = SHD_copy_conservative(arg->src,&arg->dst);
            OUTPUT_ERROR(err,arg,"Mul");
            arg->dst.addr.id =X86_REG_EDX;
            break;
        default:
            assert(0);
    }
    err = SHD_copy_conservative(arg->src,&arg->dst); //the first propagation for 1 byte case, and the 2nd otherwise.

    shad_inq flags={.addr.id=0,.type=FLAG,.size=SHD_SIZE_u8};
    SHD_copy_conservative(arg->dst,&flags);

    OUTPUT_ERROR(err,arg,"Mul");
    free(udata);
}