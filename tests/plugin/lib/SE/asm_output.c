#include "asm_generation.h"

char imm_buffer[33];

char inst_buffer[64];

const char *frmt_inst_op = "%s %s";

const char *frmt_2ops = "%s, %s";

static inline void add_size_prefix(char *buf, u16 size){ //to support concat and trunc we have other sizes in addition to the powers of 2
    char *tmp = strdup(buf);

    switch (size){
        case 0:
        case 1:
            strcpy(imm_buffer,"byte ptr");
            break;
        case 2:
            strcpy(imm_buffer,"word ptr");
            break;
        case 3:
        case 4:
            strcpy(imm_buffer,"dword ptr");
            break;
        case 5:
        case 6:
        case 7:
        case 8:
            strcpy(imm_buffer,"qword ptr");
            break;
        default:
            printf("this size in not supported yet = %d!\n",size);
            assert(0);
    }
    strcat(imm_buffer,tmp);
}

static inline const char *mem_text(x86_op_mem *eff_addr, u16 size, u8 add_pref){ //[base + (index*scale) + disp]
    char index_scale[20]={'\0'}; //10 int chars + '*' + three reg identifier chars + '\0'
    const char *base = eff_addr->base!=-1?get_qemu_reg_name(eff_addr->base,8):"";
    imm_buffer[0]='[';
    imm_buffer[1]= '\0';
    if(eff_addr->index!=-1){
        if(eff_addr->scale!=1){
            sprintf(index_scale,"%s*%d",get_qemu_reg_name(eff_addr->index,8),eff_addr->scale);
        }
        else{
            sprintf(index_scale,"%s",get_qemu_reg_name(eff_addr->index,8));
        }
    }
    if(eff_addr->base!=-1){
        sprintf(imm_buffer,"%s%s",imm_buffer,base);
    }
    if(eff_addr->index!=-1){
        if(eff_addr->base!=-1){
            sprintf(imm_buffer,"%s + %s",imm_buffer,index_scale);
        }
        else{
            sprintf(imm_buffer,"%s %s",imm_buffer,index_scale);
        }
    }
    if(eff_addr->disp){
        sprintf(imm_buffer,"%s%s%ld]",imm_buffer,eff_addr->disp>0?"+":"",eff_addr->disp);

    }
    else{
        sprintf(imm_buffer,"%s%s",imm_buffer,"]");
    }
    if(add_pref){
        add_size_prefix(imm_buffer, size);
    }
    return (const char*)imm_buffer;;
}

static inline const char *op_text(enum shadow_type type, uint64_t operand, u16 size, u8 add_pref){
    const char *str=NULL;
    switch(type){
//        case GLOBAL_IMPLICIT: //later, we can print for slice graph but not for asm
        case GLOBAL:
            if(operand<=R_HIGH){
                return get_qemu_reg_name(operand,size);
            }
            else{
                return Qreg_to_Caps_Name(operand);
            }
        case IMMEDIATE:
            sprintf(imm_buffer,"0x%lx",operand);
            str = (const char *)imm_buffer;
            break;
        case MULTIPLE_OPS:
        {
            if(operand==0){
                sprintf(imm_buffer,"%s","MULTIOPS");
            }
            else{
                multiple_operands *mulOps = (multiple_operands *)operand;
                for (int i=0;i<mulOps->num_operands;i++){
                    const char *tmp = op_text(mulOps->operands[i].type,mulOps->operands[i].operand,mulOps->operands[i].size,1);
                    if(tmp!=NULL){
                        if(str!=NULL){
                            sprintf(imm_buffer,"%s, %s",str, imm_buffer);
                        }
                        str = strdup(imm_buffer);
                    }
                }
            }
            break;
        }
//        case MEMORY_IMPLICIT:
        case MEMORY:
        case EFFECTIVE_ADDR:
            if(operand!=0){
                return mem_text((x86_op_mem *)operand,size,add_pref);
            }
            else{
                sprintf(imm_buffer,"%s",type==MEMORY?"[MEMORY]":"[$EFF_ADDR]");
            }
            str = (const char *)imm_buffer;
            break;
        default:
            return NULL;
    }
    return str;
}

static const char *print_load(inst *instruction){
    const char *format = "%s %s";
    const char *op2=NULL;
    const char *op1=NULL;
    switch (instruction->op){
        case Load:
            sprintf(inst_buffer,"Load(%d)",instruction->size);
            break;
        case Trunc:
            sprintf(inst_buffer,"Truncate(%d)",instruction->size);
            break;
        case Concat:
            sprintf(inst_buffer,"Concat(%d)",instruction->size);
            break;
        case Extract:
            sprintf(inst_buffer,"Extract(%llu)\t",instruction->op2);
            break;
        case UNION_MULTIPLE_OPS:
            inst_buffer[0] = '\0'; //for the second sprintf
            op2 = op_text(instruction->op2_type,instruction->op2,instruction->size,0);
            if(op2!=NULL){
                sprintf(inst_buffer,format,inst_buffer,op2);
                format = "%s, %s";
            }
            op1 = op_text(instruction->op1_type,instruction->op1,instruction->size,0);
            if(op1!=NULL){
                sprintf(inst_buffer,format,inst_buffer,op1);
            }
//            printf("op1=%llu, op1_type=%d, op2=%llu, op2_type=%d, operands=%s\n",instruction->op1,instruction->op1_type,instruction->op2,instruction->op2_type,inst_buffer);
            break;
        case EFFECTIVE_ADDR_UNION:
            sprintf(inst_buffer,"left (base+disp) + right (scale*index)\n");
            break; // LEA reg, [MULTIOPS(base,scale)+op1]
        case TAINT:
            sprintf(inst_buffer,"TAINT:%llu\n",instruction->op1);
            break;
        case Load_REG:
            sprintf(inst_buffer,"concrete:0x%llx\n",instruction->op1);
            break;
        case CALL_HELPER:
            sprintf(inst_buffer,"CALL\t%s",(char *)instruction->dest); //handling helper calls
            break;
        default:
            sprintf(inst_buffer,"%d",instruction->op);
            break;
    }
    return inst_buffer;
}

static inline char *print_op(char *inst_buffer, char *format, u64 op, enum shadow_type type, u16 size, u8 add_pref){
    const char *opStr = op_text(type,op,size,add_pref);
    if(opStr!=NULL){
        sprintf(inst_buffer,format,inst_buffer,opStr);
        return (char *)frmt_2ops;
    }
    else{
        return format;
    }
}
static const char *print_X86_instruction(inst *instruction){
//    const char *inst_name = GET_INST_NAME(label->op);
    int conv_size = instruction->size;
    u8 add_pref = 1;
    if((instruction->op==X86_INS_MOVZX || instruction->op==X86_INS_MOVSX || instruction->op==X86_INS_MOVSXD)){ //handling size conversion
        if(instruction->op==X86_INS_MOVSX && instruction->size==8){
            instruction->op=X86_INS_MOVSXD; //to fix an inconsistency between nasm, capstone and keystone that wouldn't accept X86_INS_MOVSX for 64 bits
        }
        if(instruction->size_src<instruction->size){
            conv_size = instruction->size_src;
        }
        else{
            instruction->op = X86_INS_MOV; //TODO: this is just a dirty fix for not having the actual operand size
        }
    }
    if(instruction->op==X86_INS_LEA){
        add_pref = 0;
    }
    const char *inst_name = get_inst_name(instruction->op);
    if(inst_name==NULL){
        if ((instruction->op >= op_start_id) && (instruction->op < op_end_id)){
            return print_load(instruction);
        }
        else{
            return NULL;
        }
    }
    inst_buffer[0] = '\0';
    sprintf(inst_buffer,"%s\t",inst_name);
    //print operands
    char *format = print_op(inst_buffer,(char *)frmt_inst_op,instruction->dest,instruction->dest_type,instruction->size,add_pref);
    format = print_op(inst_buffer,format,instruction->op2,instruction->op2_type,instruction->size,add_pref);
    format = print_op(inst_buffer,format,instruction->op1,instruction->op1_type,conv_size,add_pref); //assumes op1 and dst have the same size
    return inst_buffer;
}
