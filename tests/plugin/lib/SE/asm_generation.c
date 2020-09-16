//===-- dfsan.cc ----------------------------------------------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// DataFlowSanitizer runtime.  This file defines the public interface to
// DataFlowSanitizer as well as the definition of certain runtime functions
// called automatically by the compiler (specifically the instrumentation pass
// in llvm/lib/Transforms/Instrumentation/DataFlowSanitizer.cpp).
//
// The public interface is defined in include/sanitizer/dfsan_interface.h whose
// functions are prefixed dfsan_ while the compiler interface functions are
// prefixed __dfsan_.
//===----------------------------------------------------------------------===//
#include "dfsan.h"

//#include "../../lib/utility.c"

#include "./sanitizer_common/sanitizer_atomic.h"
#include "./sanitizer_common/sanitizer_common.h"

#include <sys/time.h>
#include <sys/resource.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <assert.h>
#include <fcntl.h>
#include <string.h>

#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "../../../../capstone/include/x86.h"
#include "../../../../capstone/include/capstone.h"
//#include "../tainting.h"
#include "../utility.h"
#include "defs.h"
#define MAX_INPUT_SIZE 1024
#define INVALID_REGISTER -1

#define IS_MEMORY(X) (u16)X==(u16)MEMORY || (u16)X==(u16)MEMORY_IMPLICIT
#define IS_GLOBAL(X) (u16)X==(u16)GLOBAL || (u16)X==(u16)GLOBAL_IMPLICIT
#define MAKE_EXPLICIT(X) X=(((u16)X==(u16)GLOBAL_IMPLICIT || (u16)X==(u16)MEMORY_IMPLICIT))?(enum shadow_type)((u16)X-1):X


typedef struct{
    u64 operand;
    enum shadow_type type;
} asm_operand;

typedef struct{
    asm_operand operands[8];
    u8 num_operands;
} multiple_operands; //would be assigned to a UNION_MULTIPLE_OPS

//We mostly use the instruction pointers in the labels, and place the missing pieces like the effective_addr, memory addresses and multiple_ops.
//We would still need more instructions for helper calls and data movements that we generate and add
//The only external data structure that we need to use is the Capstone x86_op_mem which we will need for effective address handling.
typedef struct inst_list{
    inst *ins;
    inst_list *next_inst;
} inst_list;

inst_list *instructions_head;
inst_list *instructions_tail;

struct dfsan_label_info *labels;

void *taints[MAX_INPUT_SIZE];

u32 STACK_START_OFFSET;
u32 STACK_CURRENT_OFFSET;

//the below helper_calls should be initialized for this module. The best approach is to just place the assembly code for the function
//in the beginning of the assembly stream and pass their relative offset to this module

void *CONCAT_HELPER; //func(op1,op1_size,op2,op2_size,concat_size,retaddr) shift op1 op1_size left, and 'or' it with op2 shifted right op2_size. Copy the result to retaddr.
void *TRUNCATE_HELPER; //func(op,orig_size,trunc_size,retaddr) that would shift operand orig_size-trunc_size left, then shift back right. Copy the result to retaddr.

static void *allocate_from_stack(void){
    x86_op_mem *eff_mem = (x86_op_mem *)malloc(sizeof(x86_op_mem));
    eff_mem->base = R_ESP;
    eff_mem->index = INVALID_REGISTER;
    eff_mem->disp = STACK_START_OFFSET + STACK_CURRENT_OFFSET;
    eff_mem->scale = 1;
    //eff_mem->segment = 0; //not sure what it should be
    STACK_CURRENT_OFFSET -= 8 ; //we allocate slots of 8 bytes
    return (void *)eff_mem;
}

static inline inst_list *allocate_tail(inst_list *list){
    if(list){
        list->next_inst = (inst_list *)malloc(sizeof(inst_list));
        return list->next_inst;
    }
    else{
        list = (inst_list *)malloc(sizeof(inst_list));
        return list;
    }
}

typedef void (*guest_memory_read_func)(uint64_t vaddr, int len, void *buf);

/*
 * Solving register collisions:
 * Instead of a "detect and resolve", we completely avoid it by storing the label result somewhere on the stack.
 * First, we save computation time this way. For instance, if label x is used 3 times, instead of executing its branch 3 times we execute only once.
 * Second, we would be very efficient in memory management. We only allocate label for the nodes (not the memory addresses referenced in instructions),
 * and we can release child nodes after executing the parent. In contrast, the collision can happen many times and even in nested trees.
 * Also, We would need to handle memory addresses separately that way.
 */

static inline void add_instruction(inst *instruction){
    inst_list *tail_Node = allocate_tail(instructions_tail);
    tail_Node->ins = instruction;
    instructions_tail=tail_Node;
}

inline inst_list *create_instruction(u64 op1, enum shadow_type op1_type, u64 op2, enum shadow_type op2_type, u64 dest_op, enum shadow_type dest_type,u16 dest_size,u16 op){
    inst *temp = (inst *)malloc(sizeof(inst));
    temp->op1 = op1;
    temp->op2 = op2;
    temp->dest = dest_op;
    temp->op1_type = op1_type;
    temp->op2_type = op2_type;
    temp->dest_type = dest_type;
    temp->size = dest_size;
    temp->op = op;
    add_instruction(temp);
}

inline void mov_from_to(u64 from_op, enum shadow_type from_type, u64 to_op, enum shadow_type to_type, u16 to_size){
    if (!IS_MEMORY(from_type) || !IS_MEMORY(to_type)){
        MAKE_EXPLICIT(from_type); //add_operands reject it if otherwise
        MAKE_EXPLICIT(to_type);
        create_instruction(from_op,from_type,0,UNASSIGNED,to_op,to_type,to_size,X86_INS_MOVZX);
    }
#if 0
        else{ //both are mem, we can't use mov;
        MAKE_EXPLICIT(dest_type);
        create_instruction(from_op,from_type,0,UNASSIGNED,0,UNASSIGNED,to_size,X86_INS_PUSH);

        MAKE_EXPLICIT(op1_type);
        create_instruction(to_op,to_type,0,UNASSIGNED,0,UNASSIGNED,to_size,X86_INS_POP);
    }
#else
    else{
        printf("just use that memory address, why would you incur the move?");
        assert(0);
    }
#endif
}

inline inst_list *create_instruction_label(dfsan_label_info *label){
    inst *instruction = &(label->instruction);
    add_instruction(instruction);;
    //store the result somewhere on the stack
    label->label_mem = allocate_from_stack();
    mov_from_to(instruction->dest,instruction->dest_type,(u64)label->label_mem,MEMORY,instruction->size); //move the result to the stack space
    //we can free the child nodes labels, but for now we just consume stack that wouldn't be a problem is the slice is not too large.
}

static inline void copy_parameter_n(int i, u64 param, enum shadow_type type, u16 size){
    u64 dest;
    switch (i){
        case 1:
            dest = R_EDI;
            break;
        case 2:
            dest = R_ESI;
            break;
        case 3:
            dest = R_EDX;
            break;
        case 4:
            dest = R_ECX;
            break;
        case 5:
            dest = R_R8;
            break;
        case 6:
            dest = R_R9;
            break;
        default:
            printf("not supported yet!\n");
            assert(0);
    }
    mov_from_to(param,type,dest,GLOBAL,size);
}

/*The two helpers will place instructions to perform the following:
 * 1. Allocate a stack space for the result
 * 2. Prepare the callee parameters
 * 3. Increment the stack pointer (parameters size)
 * 4. Call
 * 5. Decrement the stack pointer
*/
void *callHelperTruncate(u64 operand, u16 orig_size, u16 trunc_size){
    void *res=allocate_from_stack();
    //prepare the parameters
    copy_parameter_n(1,operand,MEMORY,8);
    copy_parameter_n(2,orig_size,IMMEDIATE,8); //8 so the 8 bytes destination would be used, and the rest of unused bytes would be cleared.
    copy_parameter_n(3,trunc_size,IMMEDIATE,8);
    copy_parameter_n(4,(u64)res,MEMORY,8);
    //Increment the stack pointer
    create_instruction(0,UNASSIGNED,0,UNASSIGNED,R_ESP,GLOBAL,32,X86_INS_INC); //4 parameters of 8 bytes
    //call
    create_instruction(0,UNASSIGNED,0,UNASSIGNED,(u64)TRUNCATE_HELPER,IMMEDIATE,2,X86_INS_CALL); //should be a call to a relative address
    //Decrement the stack pointer
    create_instruction(0,UNASSIGNED,0,UNASSIGNED,R_ESP,GLOBAL,32,X86_INS_DEC);
    return res;
}

void *callHelperConcat(u64 op1, u16 op1_size, u64 op2, u16 op2_size,u16 concat_size){
    void *res=allocate_from_stack();
    //prepare the parameters
    copy_parameter_n(1,op1,MEMORY,8);
    copy_parameter_n(2,op1_size,IMMEDIATE,8); //8 so the 8 bytes destination would be used, and the rest of unused bytes would be cleared.
    copy_parameter_n(3,op2,MEMORY,8);
    copy_parameter_n(4,op2_size,IMMEDIATE,8);
    copy_parameter_n(5,concat_size,IMMEDIATE,8);
    copy_parameter_n(6,(u64)res,MEMORY,8);
    //Increment the stack pointer
    create_instruction(0,UNASSIGNED,0,UNASSIGNED,R_ESP,GLOBAL,48,X86_INS_INC); // 6 paramters of 8 bytes
    //call
    create_instruction(0,UNASSIGNED,0,UNASSIGNED,(u64)CONCAT_HELPER,IMMEDIATE,2,X86_INS_CALL); //should be a call to a relative address
    //Decrement the stack pointer
    create_instruction(0,UNASSIGNED,0,UNASSIGNED,R_ESP,GLOBAL,48,X86_INS_DEC);
    return res;
}

inline int add_operands(u64 op1, enum shadow_type op1_type, asm_operand *ret){
    int i = 0;
    if(op1_type==MULTIPLE_OPS){
        assert(op1>0);
        multiple_operands *loperands = (multiple_operands *)op1;
        for(i=0;i<loperands->num_operands;i++){
            ret[i] = loperands->operands[i];
        }
    }
    else if(op1_type==EFFECTIVE_ADDR || op1_type==GLOBAL || op1_type==IMMEDIATE || op1_type==MEMORY){
        if(op1_type==EFFECTIVE_ADDR) assert(op1>0);
        ret[i].operand = op1; //can still keep the Qemu register ID here until the instruction creation
        ret[i].type = op1_type;
        i++;
    }
    //else if op is implicit or unassigned, ignore
    return i;
}

void merge_ops(u64 op1, enum shadow_type op1_type, u64 op2, enum shadow_type op2_type,multiple_operands *ret){
    int i,j=0;

    i = add_operands(op1,op1_type,&(ret->operands[0]));
    j = add_operands(op2,op2_type,&(ret->operands[i]));

    ret->num_operands = i + j;
}

inline void prepare_operand(dfsan_label label, u64 *op1, enum shadow_type op1_type, u16 size){ //move from label placeholder, instead of the operand itself
    u64 dest = labels[label].instruction.dest;
    u16 dest_type = labels[label].instruction.dest_type;
    if (dest_type==UNION_MULTIPLE_OPS || dest_type==EFFECTIVE_ADDR_UNION){
        assert(dest>0);
        assert(dest_type==op1_type);
        *op1 = dest;
    }
    else if(IS_MEMORY(op1_type)){ //no need to move, just use the pointer to the label effective address
        *op1 = dest; //op1 now has
    }
    else if (IS_GLOBAL(op1_type)){ //we have to move
        mov_from_to((u64)labels[label].label_mem,MEMORY,*op1,op1_type,size); //Note that even memory loads(Load, Taint, Concat) would be handled correctly this way
    }
    //else it is either IMM or not assigned
}

void generate_asm(int root){
    struct dfsan_label_info *label = &labels[root];
    if(label->label_mem!=0){
        return; //we already evaluated this label, in another subtree; just use the value stored in label_mem
    }
    if(label->l1!=CONST_LABEL){
        generate_asm(label->l1);
        prepare_operand(label->l1,&(label->instruction.op1), label->instruction.op1_type, label->instruction.size); //move the data from l1 to op1
        //if op1 is occupied, will push its previous value
    }
    if(label->l2!=CONST_LABEL){ // by appending to latest_node, we merge left and right labels)
        generate_asm(label->l2);
        prepare_operand(label->l2,&(label->instruction.op2), label->instruction.op2_type, label->instruction.size); //move the data from l1 to op2
        //if op2 is occupied, will push its previous value
    }
    if(label->instruction.dest==0 && (label->instruction.op>=op_start_id && label->instruction.op<op_end_id)){
        switch (label->instruction.op) {
            case Load_REG:
                label->label_mem = allocate_from_stack();
                mov_from_to(label->instruction.op1,label->instruction.op1_type,(u64)label->label_mem,MEMORY,label->instruction.size);
                break;
            case TAINT:
            case Load:
                label->label_mem = taints[labels[label->l1].instruction.op1]; //op1 is expected to have the legit offset
                label->instruction.dest = (u64)label->label_mem;
                break;
            case Trunc:
                label->label_mem = callHelperTruncate((u64)labels[label->l1].label_mem, labels[label->l1].instruction.size,
                                                label->instruction.size); //what about the dest.type; probably memory
                label->instruction.dest = (u64)label->label_mem;
                break;
            case Concat:{
                dfsan_label_info *l1_label = &(labels[label->l1]);
                dfsan_label_info *l2_label = &(labels[label->l2]);
                label->label_mem = callHelperConcat((u64)l1_label->label_mem, l1_label->instruction.size, (u64)l2_label->label_mem,
                                                   l2_label->instruction.size, label->instruction.size);
                label->instruction.dest = (u64)label->label_mem;
                break;
            }
            case UNION_MULTIPLE_OPS: {
                multiple_operands *ret = (multiple_operands *) calloc(1, sizeof(multiple_operands));
                memset(ret, 0, sizeof(multiple_operands));
                merge_ops(label->instruction.op1, label->instruction.op1_type, label->instruction.op2,
                          label->instruction.op2_type, ret);
                assert(ret->num_operands > 0);
                label->instruction.dest = (u64)ret;
                break;
            }
                //would need register occupation because they would be immediately used; we occupy them in the caller
            case EFFECTIVE_ADDR_UNION:{
                dfsan_label_info *l1_label = &(labels[label->l1]); //assemble the effective address based on the contract
                dfsan_label_info *l2_label = &(labels[label->l2]);
                x86_op_mem *eff_mem = (x86_op_mem *)malloc(sizeof(x86_op_mem));
                eff_mem->index = l1_label->instruction.op1; //note that we are storing Qemu based register IDs
                eff_mem->scale = l1_label->instruction.op2;
                eff_mem->base = l2_label->instruction.op1;
                eff_mem->disp = l2_label->instruction.op2;
                label->instruction.dest = (u64)eff_mem;
                break;
            }
            case Nop:
                break;
            default:
                printf("operation case is not supported!\n");
                assert(0);
        }
    }
    else{
        //register collision will not happen
        //before this line, the transfer between the child dest and the operand should be done; for multiple_ops and effective we need to just copy the pointer while for other types we need a mov instruction
        create_instruction_label(label);
    }
}