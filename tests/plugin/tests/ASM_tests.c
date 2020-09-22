//
// Created by sina on 2020-07-08.
//
/* For testing, follow these steps:
 * comment SANITIZER_CAN_USE_PREINIT_ARRAY in dfsan.h
 * Install Capstone
 * g++ -pie -fPIE -fPIC -shared -std=gnu++11 -o dfsan.o dfsan.cc `pkg-config --cflags glib-2.0` `pkg-config --libs glib-2.0`
 * gcc  -o ASM_test.o  -Wall -lcapstone  ./tests/ASM_tests.c `pkg-config --cflags glib-2.0` `pkg-config --libs glib-2.0` ./lib/SE/dfsan.o ./lib/SE/union_util.o ./lib/SE/union_hashtable.o ./lib/SE/taint_allocator.o
*/
#define TEST_ASM_GENERATION

#define GLOBAL_POOL_SIZE 254

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <sys/file.h>
#include <sys/mman.h>

#include <glib.h>

#include "../lib/SE/dfsan_interface.h"

#include "../lib/SE/asm_generation.c"
#include "../lib/utility.c"

#define dfsan_union_noop(x,y,z,w) dfsan_union(x,y,z,w,0,0,UNASSIGNED,UNASSIGNED,0,UNASSIGNED)

//#define NUM_TAINTS 8
//
//#define FIRST_VAR_OFFSET 16 //should change based on NUM_TAINTS

void *res;

char imm_buffer[33];

char inst_buffer[64];


static inline const char *mem_text(x86_op_mem *eff_addr){ //[base + (index*scale) + disp]
    char index_scale[20]={'\0'}; //10 int chars + '*' + three reg identifier chars + '\0'
    const char *base = eff_addr->base!=-1?Qreg_to_Caps_Name(eff_addr->base):"";
    imm_buffer[0]='[';
    imm_buffer[1]= '\0';
    if(eff_addr->index!=-1){
        if(eff_addr->scale!=1){
            sprintf(index_scale,"%s*%d",Qreg_to_Caps_Name(eff_addr->index),eff_addr->scale);
        }
        else{
            sprintf(index_scale,"%s",Qreg_to_Caps_Name(eff_addr->index));
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
    return (const char*)imm_buffer;;
}

static inline const char *op_text(enum shadow_type type, uint64_t operand){
    switch(type){
        case GLOBAL:
            return Qreg_to_Caps_Name(operand);
        case IMMEDIATE:
            sprintf(imm_buffer,"0x%lx",operand);
            break;
        case MULTIPLE_OPS:
            sprintf(imm_buffer,"%s","MULTIOPS");
            break;
        case MEMORY:
        case EFFECTIVE_ADDR:
            if(operand!=0){
                return mem_text((x86_op_mem *)operand);
            }
            else{
                sprintf(imm_buffer,"%s",type==MEMORY?"[MEMORY]":"[$EFF_ADDR]");
            }
            break;
        default:
            return NULL;
    }
    return (const char*)imm_buffer;
}

static const char *print_load(inst *instruction){
    const char *format = "%s";
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
            op2 = op_text(instruction->op2_type,instruction->op2);
            if(op2!=NULL){
                sprintf(inst_buffer,format,op2);
                format = "%s, %s";
            }
            op1 = op_text(instruction->op1_type,instruction->op1);
            if(op1!=NULL){
                sprintf(inst_buffer,format,inst_buffer,op1);
            }
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

static const char *print_X86_instruction(inst *instruction){
//    const char *inst_name = GET_INST_NAME(label->op);

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
    const char *format = "%s %s";

    const char *op3 = op_text(instruction->dest_type,instruction->dest);
    if(op3!=NULL){

        sprintf(inst_buffer,format,inst_buffer,op3);
        format = "%s, %s";
    }

    const char *op2 = op_text(instruction->op2_type,instruction->op2);
    if(op2!=NULL){
        sprintf(inst_buffer,format,inst_buffer,op2);
        format = "%s, %s";
    }

    const char *op1 = op_text(instruction->op1_type,instruction->op1);
    if(op1!=NULL){
        sprintf(inst_buffer,format,inst_buffer,op1);
    }

    return inst_buffer;
}

void test_create_asm(){
    char asm_code[1024]={'\0'};
    uint32_t pos1 = 0x0001;

    dfsan_label l1=dfsan_create_label(pos1++);
    assert(l1>0);

    dfsan_label l2=dfsan_create_label(pos1);

    int sz = 4;

//    void *addr1 = (void *)0x700000847600;
//    void *addr2 = (void *)0x807f00;

    dfsan_label l3 = dfsan_union_noop(l1, l2, Add, 1);

    dfsan_label_info *l3_info=dfsan_get_label_info(l3);

//    create_instruction_label(l3_info);
//    for(inst_list *temp=instructions_head;temp!=NULL;temp=temp->next_inst){
//        const char *asm_ins_txt=print_X86_instruction(temp->ins);
//        printf("%s\n",asm_ins_txt);
//    }

    int reg_id = 21;

    dfsan_set_register_label(reg_id, l1);
    dfsan_label t1 = dfsan_get_register_label(reg_id);
    assert(t1==l1);


    void *taint_start_addr = (void *)0x8075f0;
    for(int i=0;i<sz;i++){
        dfsan_label lload=dfsan_create_label(pos1++);
        assert(lload>0);
        dfsan_set_label(lload,taint_start_addr+i,1);
    }

    //create_instruction_label
    printf("testing create_instruction_label by checking the assembly text...\n");
    void *taint_2nd_addr = (void *)0x8075ec;
    for(int i=0;i<sz;i++){
        dfsan_label lload=dfsan_create_label(pos1++);
        assert(lload>0);
        dfsan_set_label(lload,taint_2nd_addr+i,1);
    }
    dfsan_label taint_concat_labels = dfsan_read_label(taint_2nd_addr,8);

    dfsan_label addLabel = dfsan_union(t1, taint_concat_labels, Add, sz,
                reg_id, (u64)taint_2nd_addr, GLOBAL, MEMORY, reg_id,  GLOBAL_IMPLICIT);

    dfsan_label_info *add_info = dfsan_get_label_info(addLabel);
    add_info->instruction.op2 = (u64)allocate_from_stack(8);
    create_instruction_label(add_info);
    for(inst_list *temp=instructions_head;temp!=NULL;temp=temp->next_inst){
        const char *asm_ins_txt=print_X86_instruction(temp->ins);
        assert(asm_ins_txt!=NULL);
        sprintf(asm_code,"%s%s\n",asm_code,asm_ins_txt);
    }
    char *test1="add\t [spl-12], rip\nmovzx\t [spl-20], rip\n";
    int st1=strcmp(asm_code,test1);
    assert(st1==0);

    //prepare_operand
    printf("testing prepare_operand by checking assembly instruction text...\n");
    inst_list *new_head = instructions_tail;
    int eax_reg_id = 0;
//    int ebx_reg_id = 3;
    dfsan_label andLabel = dfsan_union(t1, addLabel, And, sz,
                                       eax_reg_id, 16, GLOBAL, IMMEDIATE, eax_reg_id,  GLOBAL_IMPLICIT);
    dfsan_label_info *and_info = dfsan_get_label_info(andLabel);
    prepare_operand(addLabel,&(and_info->instruction.op1),and_info->instruction.op1_type,and_info->instruction.size);

    char *test2="movzx\t rax, [spl-20]";
    for(inst_list *temp=new_head->next_inst;temp!=NULL;temp=temp->next_inst){
        const char *asm_ins_txt=print_X86_instruction(temp->ins);
        assert(asm_ins_txt!=NULL);
        int st2=strcmp(asm_ins_txt,test2);
        assert(st2==0);
        sprintf(asm_code,"%s%s\n",asm_code,asm_ins_txt);
    }

    //concat helper call
    printf("testing callHelperConcat case in generate_asm by going over the generated instructions...\n"); // Load case will be also tainted

    dfsan_label_info *concat_label_info = dfsan_get_label_info(taint_concat_labels);
    new_head = instructions_tail;

    generate_asm(taint_concat_labels);
    int i=0;
    for(inst_list *temp=new_head->next_inst;temp!=NULL;temp=temp->next_inst,i++){
        const char *asm_ins_txt=print_X86_instruction(temp->ins);
        sprintf(asm_code,"%s%s\n",asm_code,asm_ins_txt);
        switch (i){
            case 0:
            {
                assert(temp->ins->op==X86_INS_MOVZX);
                assert(temp->ins->op1!=0);
                x86_op_mem *mem = ((x86_op_mem *)temp->ins->op1);
                assert(mem->disp==-6); //this is the first operand of concat helper (taint_2nd_addr), and it is supposed to be at sp-6 (2 for the initial pos1 label creation, and 4 for the first loop above)
                break;
            }
            case 1:
            {
                assert(temp->ins->op==X86_INS_MOVZX);
                assert(temp->ins->op1==4); //size of the first operand is 4
                break;
            }
            case 2:
            {
                assert(temp->ins->op==X86_INS_MOVZX);
                assert(temp->ins->op1!=0);
                x86_op_mem *mem = ((x86_op_mem *)temp->ins->op1);
                assert(mem->disp==-2); //this is the second operand of concat helper (taint_start_addr), and it is supposed to be at sp-2 (2 for the initial pos1 label creation)
                break;
            }
            case 3:
            {
                assert(temp->ins->op==X86_INS_MOVZX);
                assert(temp->ins->op1==4); //size of the second operand is 4
                break;
            }
            case 4:
            {
                assert(temp->ins->op==X86_INS_MOVZX);
                assert(temp->ins->op1==8); //new size after concat is 8
                break;
            }
            case 5:
            {
                assert(temp->ins->op==X86_INS_LEA);
                assert(temp->ins->op1!=0);
                x86_op_mem *mem = ((x86_op_mem *)temp->ins->op1);
                assert(mem->disp==-28); //Pointer for the ret value(the concat result). That's based on the stack we so far used.

                break;
            }
            case 6:
            {
                assert(temp->ins->op==X86_INS_ADD);
                assert(temp->ins->op2!=0x24); //based on the stack we so far used and a 8 bytes gap
                break;
            }
            case 7:
            {
                assert(temp->ins->op==CALL_HELPER);
                break;
            }
            case 8:
            {
                assert(temp->ins->op==X86_INS_SUB);
                assert(temp->ins->op2!=0x24); //based on the stack we so far used and a 8 bytes gap
                break;
            }
            default:
                break;
        }
    }
//    printf("%s",asm_code);

    //Multiple operands and Effective Address
    printf("testing Multiple operands and Effective Address...\n");
    new_head = instructions_tail;
    reg_id = 0;
    dfsan_label ml3 = dfsan_union(l1, CONST_LABEL, UNION_MULTIPLE_OPS , 8,
                     reg_id, 8, GLOBAL, IMMEDIATE, 0, UNASSIGNED); //we need the union regardless of l1 status because of MULTIPLE_OPS
    reg_id = 3;
    dfsan_label ml4 = dfsan_union(l2, CONST_LABEL, UNION_MULTIPLE_OPS , 8,
                     reg_id, 2, GLOBAL, IMMEDIATE, 0, UNASSIGNED); //we need the union regardless of l2 status


    dfsan_label eff_label = dfsan_union(ml3, ml4, EFFECTIVE_ADDR_UNION, 0,
                     0, 0, MULTIPLE_OPS, MULTIPLE_OPS, 0,  EFFECTIVE_ADDR);

    dfsan_label lea_label = dfsan_union(eff_label, CONST_LABEL, X86_INS_LEA, 8,
                            0, 0, EFFECTIVE_ADDR, UNASSIGNED, reg_id,  GLOBAL);

    generate_asm(lea_label);

    for(inst_list *temp=new_head->next_inst;temp!=NULL;temp=temp->next_inst,i++){
        const char *asm_ins_txt=print_X86_instruction(temp->ins);
        sprintf(asm_code,"%s%s\n",asm_code,asm_ins_txt);
        switch (i){
            case 0:
            {
                assert(temp->ins->op==X86_INS_MOVZX);
                assert(temp->ins->op1!=0);
                x86_op_mem *mem = ((x86_op_mem *)temp->ins->op1);
                assert(mem->disp==-1); //It's simply the first raw byte TAINT
                break;
            }
            case 1:
            {
                assert(temp->ins->op==X86_INS_MOVZX);
                assert(temp->ins->op1==4); //It's simply the second raw byte TAINT
                break;
            }
            case 2:
            {
                assert(temp->ins->op==X86_INS_LEA);
                char *test_lea="lea\t rbx, [rbx + rax*8+2]"; //see ml3 and ml4 for why *8 and +2
                int lt=strcmp(asm_ins_txt,test_lea);
                assert(lt==0);
                break;
            }
            default:
                break;
        }

    }
    printf("%s",asm_code);

}

__attribute__((section(".preinit_array")))
static void (*dfsan_init_ptr)(void) = dfsan_init;

void mem_read(uint64_t vaddr, int len, void *buf)
{
    switch (vaddr){
        case 0x8075f4:
            ((char *)buf)[0]=0x0c;
            break;
        case 0x700000847600:
            ((char *)buf)[0]=0xd0;
            ((char *)buf)[1]=0xf1;
            ((char *)buf)[2]=0x0f;
            break;
        default:
            ((char *)buf)[0]=0x00;
            break;
    }
}

void reg_read(uint32_t reg, int len, void *buf)
{
    switch (reg){
        case 0x1:
            ((char *)buf)[0]=0x0d;
            break;
        case 0x2:
            ((char *)buf)[0]=0x01;
            ((char *)buf)[1]=0xff;
            break;
        case 0x3:
            ((char *)buf)[0]=0x01;
            ((char *)buf)[1]=0xff;
            ((char *)buf)[2]=0xc0;
            ((char *)buf)[1]=0x00;
            break;
        default:
            ((char *)buf)[0]=0x00;
            break;
    }
}


static dfsan_settings settings = {.readFunc=&mem_read, .regValue=&reg_read, .printInst=&print_X86_instruction};

int main(){
    init_register_mapping();
    init_asm_generation(12); //assertions change if more bytes
    dfsan_init(&settings);
//    test_shadow_mem();
    test_create_asm();
    return 0;
}