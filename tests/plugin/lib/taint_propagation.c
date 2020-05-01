//
// Created by sina on 4/20/2020.
//
//#include <stdint.h>
#include <limits.h>
#include "shadow_memory.h"
#include "taint_propagation.h"

uint64_t rotate_op(uint64_t n, uint64_t c, shift_op op);

uint64_t rotate_op(uint64_t n, uint64_t c, shift_op op){
    const uint64_t mask = MASK(n);
    c = DO_MASK(c,mask);
    uint64_t res = 0;
    switch (op){
        case Rol:
            res = (n<<c) | (n>> DO_MASK(-c,mask));
            break;
        case Ror:
            res = (n>>c) | (n<< DO_MASK(-c,mask));
            break;
        default:
            assert(0);
    }
    return res;
}

shadow_err SHD_clear(shad_inq *src){
    SHD_value zero = 0;
    SHD_set_shadow(src,&zero);
    return 0;
}

shadow_err SHD_copy(shad_inq src, shad_inq *dst){
    SHD_value s_val = SHD_get_shadow(src);
    shadow_err r = SHD_set_shadow(dst,&s_val);
    return r;
}

shadow_err SHD_cast(void *src,SHD_SIZE old_size,void *res, SHD_SIZE new_size){ //this is different than convert_value
    uint8_t buf[SHD_SIZE_MAX]={0};
    uint64_t s_v = convert_value(src,old_size);
    switch (new_size){
        case SHD_SIZE_u8:
            RULE_PES_APPLY(s_v,DEREF_TYPE(buf,uint8_t));
            *(uint8_t*)res = DEREF_TYPE(buf,uint8_t);
            break;
        case SHD_SIZE_u16:
            RULE_PES_APPLY(s_v,DEREF_TYPE(buf,uint16_t));
            *(uint16_t*)res = DEREF_TYPE(buf,uint16_t);
            break;
        case SHD_SIZE_u32:
            RULE_PES_APPLY(s_v,DEREF_TYPE(buf,uint32_t));
            *(uint32_t*)res = DEREF_TYPE(buf,uint32_t);
            break;
        case SHD_SIZE_u64:
            RULE_PES_APPLY(s_v,DEREF_TYPE(buf,uint64_t));
            *(uint64_t*)res = DEREF_TYPE(buf,uint64_t);
            break;
        default:
            assert(0);
    }
//    printf("cast(): old_value=%llx, new_val=%llx\n",s_v,*res);
    return 0;
}

shadow_err SHD_union(shad_inq src, shad_inq *dst){
    SHD_value s_val = SHD_get_shadow(src);
    SHD_value d_val = SHD_get_shadow(*dst);
    SHD_value res = RULE_UNION(s_val,d_val);
    shadow_err r = SHD_set_shadow(dst,&res);
    return r;
}

shadow_err SHD_add_sub(shad_inq src, shad_inq *sd){
    SHD_value s_val = SHD_get_shadow(src);
    SHD_value d_val = SHD_get_shadow(*sd);
    SHD_value res = RULE_LEFT(RULE_UNION(s_val,d_val));
    shadow_err r = SHD_set_shadow(sd,&res);
    return r;
}

shadow_err SHD_extensionL(shad_inq src, shad_inq *dst){
    SHD_value s_val = SHD_get_shadow(src);
    SHD_value res = RULE_LEFT(s_val);
    SHD_set_shadow(dst,&res);
    return 0;
}

shadow_err SHD_exchange(shad_inq *src, shad_inq *dst){
    SHD_value s_val = SHD_get_shadow(*src);
    SHD_value d_val = SHD_get_shadow(*dst);
    shadow_err r1 = SHD_set_shadow(dst,&s_val);
    shadow_err r2 = SHD_set_shadow(src,&d_val);
    return r1 | r2;
}

shadow_err SHD_and_or(shad_inq src, shad_inq *dst, uint8_t *src_val, uint8_t *dst_val, logical_op op){
    SHD_value sh_src, sh_dst;
    uint64_t op1_v, op2_v;
    if(src.type==IMMEDIATE){
        sh_src = 0;
        op1_v = src.addr.vaddr;
    }
    else{
        op1_v = convert_value(src_val,src.size);
        sh_src = SHD_get_shadow(src);
    }
    if(src.type==IMMEDIATE){
        sh_dst = 0;
        op2_v = dst->addr.vaddr;
    }
    else{
        op2_v = convert_value(dst_val,dst->size);
        sh_dst = SHD_get_shadow(*dst);
    }
    SHD_value res = 0;
    switch (op){
        case OP_AND:
            res = RULE_AND_OR(op1_v, sh_src, op2_v, sh_dst, RULE_IMPROVE_AND);
            break;
        case OP_OR:
            res = RULE_AND_OR(op1_v, sh_src, op2_v, sh_dst, RULE_IMPROVE_OR);
            break;
        default:
            printf("OP_AND=%d, OP_AND=%d, op=%d\n",OP_AND,OP_OR,op);
            assert(0);
    }
    shadow_err r = SHD_set_shadow(dst,&res);
    return r;
}

shadow_err SHD_Shift_Rotation(shad_inq src, shad_inq *dst, shift_op op){
    SHD_value d_val, s_val, shift_res;
    d_val = SHD_get_shadow(*dst);
    s_val = 0;
    if (src.type!=IMMEDIATE){
        SHD_value temp1= SHD_get_shadow(src);
        SHD_cast(&temp1,src.size,&s_val,dst->size);
    }
    switch (op){
        case Shr:
            shift_res = d_val > src.addr.vaddr;
            break;
        case Shl:
            shift_res = d_val < src.addr.vaddr;
            break;
        case Sar:
            shift_res = d_val >> src.addr.vaddr;
            break;
//        case Sal: //not included in memcheck shift rules
//            shift_res = d_val << src.addr.vaddr;
//            break;
        case Ror:
        case Rol:
            shift_res = rotate_op(d_val,src.addr.vaddr,op);
            break;
        default:
            assert(0);
    }
    d_val = RULE_UNION(s_val,shift_res);
    SHD_set_shadow(dst,&d_val);
    return 0;
}

shadow_err SHD_copy_conservative(shad_inq src, shad_inq *dst){
    SHD_value dst_shadow= SHD_get_shadow(src);
    uint8_t value[SHD_SIZE_MAX] = {0};
    SHD_cast(&dst_shadow, sizeof(SHD_value),value, dst->size);
    SHD_set_shadow(dst,&value);
    return 0;
}

