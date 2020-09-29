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

//#include "../../lib/utility.c"
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
#include "asm_generation.h"
#include "asm_output.c"
#include "../../../../capstone/include/x86.h"
#include "../../../../capstone/include/capstone.h"
//#include "../tainting.h"
#include "../utility.h"
#include "dfsan_interface.h"

#define MAX_INPUT_SIZE 1024 //change it as needed; not sure how large it can be since we use caller stack and here we also aggressively use stack without cleaning
#define INVALID_REGISTER -1

#define MAKE_EXPLICIT(X) X=(((u16)X==(u16)GLOBAL_IMPLICIT || (u16)X==(u16)MEMORY_IMPLICIT))?(enum shadow_type)((u16)X-1):X

print_instruction printInst;

//We mostly use the instruction pointers in the labels, and place the missing pieces like the effective_addr, memory addresses and multiple_ops.
//We would still need more instructions for helper calls and data movements that we generate and add
//The only external data structure that we need to use is the Capstone x86_op_mem which we will need for effective address handling.
typedef struct inst_list {
    inst *ins;
    struct inst_list *next_inst;
} inst_list;

inst_list *instructions_head;
inst_list *instructions_tail;

void *taints[MAX_INPUT_SIZE];

s32 STACK_START_OFFSET;
s32 STACK_CURRENT_OFFSET;
s32 TAINT_CURRENT_OFFSET;
s32 INPUT_SIZE;
//the below helper_calls should be initialized for this module. The best approach is to just place the assembly code for the function
//in the beginning of the assembly stream and pass their relative offset to this module

x86_op_mem *STACK_TOP;
u16 stack_top_size=0;

void *CONCAT_HELPER; //func(op1,op1_size,op2,op2_size,concat_size,retaddr) shift op1 op1_size left, and 'or' it with op2 shifted right op2_size. Copy the result to retaddr.
void *TRUNCATE_HELPER; //func(op,orig_size,trunc_size,retaddr) that would shift operand orig_size-trunc_size left, then shift back right. Copy the result to retaddr.

// +--------------------+
// |    Past frames     |
// |                    |
// +--------------------+ Stack Base + num_tainted_bytes
// |       Taints       |
// +--------------------+ Stack Base (Before the slice, the prologue copies the taints and subtracts num_tainted_bytes from esp)
// +--------------------+
// |    Other labels    |
// +--------------------+ STACK_TOP (initially Stack Base, but changes based on allocations)

static inline void *initialize_taints_addrs(int size) {
    x86_op_mem *eff_mem = (x86_op_mem *) malloc(sizeof(x86_op_mem));
    eff_mem->base = R_ESP;
    eff_mem->index = INVALID_REGISTER;
    eff_mem->disp = STACK_START_OFFSET + TAINT_CURRENT_OFFSET;
//    printf("disp=%d, TAINT_START_OFFSET=%d, TAINT_CURRENT_OFFSET=%d\n",eff_mem->disp,TAINT_START_OFFSET,TAINT_CURRENT_OFFSET);
    eff_mem->scale = 1;
    //eff_mem->segment = 0; //not sure what it should be
    TAINT_CURRENT_OFFSET += size; //we allocate slots of 8 bytes
    return (void *) eff_mem;
}


static inline void *allocate_from_stack(int size) {
    x86_op_mem *eff_mem = (x86_op_mem *) malloc(sizeof(x86_op_mem));
    STACK_CURRENT_OFFSET -= size; //large enough for the variable
    eff_mem->base = R_ESP;
    eff_mem->index = INVALID_REGISTER;
    eff_mem->disp = STACK_START_OFFSET + STACK_CURRENT_OFFSET;
    eff_mem->scale = 1;
    //eff_mem->segment = 0; //not sure what it should be
    STACK_TOP = eff_mem;
    stack_top_size = size;
    return (void *) eff_mem;
}

static void init_asm_generation(int num_tainted_bytes){
    INPUT_SIZE = num_tainted_bytes;
    STACK_CURRENT_OFFSET = TAINT_CURRENT_OFFSET = 0; //no bp push, we have our own prologue and way of accessing locals (we directly use sp)
    STACK_START_OFFSET = 0 - num_tainted_bytes; //Assume the num_tainted_bytes were copied into this frame
    assert(num_tainted_bytes<MAX_INPUT_SIZE);
    for (int i=0;i<num_tainted_bytes;i++){
        taints[i] = initialize_taints_addrs(1);
    }
    stack_top_size = 0;
    STACK_TOP = NULL;
    CONCAT_HELPER = (void *)strdup(CONCAT_HELPER_NAME);
    TRUNCATE_HELPER = (void *)strdup(TRUNC_HELPER_NAME);
}

static inline inst_list *allocate_tail(inst_list *list) {
    if (list) {
        inst_list *temp = (inst_list *) malloc(sizeof(inst_list));
        temp->next_inst = NULL;
        list->next_inst = temp;
        return temp;
    } else {
        instructions_head = list = (inst_list *) malloc(sizeof(inst_list));
        return list;
    }
}

/*
 * Solving register collisions:
 * Instead of a "detect and resolve", we completely avoid it by storing the label result somewhere on the stack.
 * First, we save computation time this way. For instance, if label x is used 3 times, instead of executing its branch 3 times we execute only once.
 * Second, we would be very efficient in memory management. We only allocate label for the nodes (not the memory addresses referenced in instructions),
 * and we can release child nodes after executing the parent. In contrast, the collision can happen many times and even in nested trees.
 * Also, We would need to handle memory addresses separately that way.
 */

static inline void add_instruction(inst *instruction) {
//    AOUT("instruction.op = %d, size=%d instruction.op1 = 0x%llx, instruction.op1_type =%d, instruction.op2 = 0x%llx, instruction.op2_type = %d, instruction.dest = 0x%llx, instruction.dest_type = %d\n",
//         instruction->op, instruction->size,
//                 instruction->op1, instruction->op1_type, instruction->op2, instruction->op2_type, instruction->dest,
//         instruction->dest_type);
    inst_list *tail_Node = allocate_tail(instructions_tail);
    tail_Node->ins = instruction;
    instructions_tail = tail_Node;
}

static inline void
create_instruction(u64 op1, enum shadow_type op1_type, u64 op2, enum shadow_type op2_type, u64 dest_op,
                   enum shadow_type dest_type, u16 dest_size, u16 op, u16 src_size) {
    inst *temp = (inst *) malloc(sizeof(inst));
    temp->op1 = op1;
    temp->op2 = op2;
    temp->dest = dest_op;
    temp->op1_type = op1_type;
    temp->op2_type = op2_type;
    temp->dest_type = dest_type;
    temp->size = dest_size;
    temp->op = op;
    temp->size_src = src_size;
    add_instruction(temp);
}

static inline void
mov_from_to(u64 from_op, enum shadow_type from_type, u64 to_op, enum shadow_type to_type, u16 to_size, u16 src_size, u8 is_ptr) { //TODO: we would need the from size and the size specifier in the asm e.g. word, byte etc.
    assert(from_type!=0 && to_type!=0);
    if (!IS_MEMORY(from_type) || !IS_MEMORY(to_type)) {
        MAKE_EXPLICIT(from_type); //add_operands reject it if otherwise
        MAKE_EXPLICIT(to_type);
        if(is_ptr){
            create_instruction(from_op, from_type, 0, UNASSIGNED, to_op, to_type, to_size, X86_INS_LEA, src_size);
        }
        else if(from_type==to_type && from_op==to_op){
            return ;
        }
        else if (IS_GLOBAL(from_type) && from_op==FLAG_REG){
            create_instruction(0, UNASSIGNED, 0, UNASSIGNED, 0, UNASSIGNED, 1, X86_INS_LAHF, 1);
            create_instruction(R_AH, GLOBAL, 0, UNASSIGNED, to_op, to_type, 1, X86_INS_MOV, 1); //zero extended that should be safe
        }
        else if (IS_GLOBAL(to_type) && to_op==FLAG_REG){
            create_instruction(from_op, from_type , 0, UNASSIGNED, R_AH, GLOBAL, 1, X86_INS_MOV, 1);
            create_instruction(0, UNASSIGNED, 0, UNASSIGNED, 0, UNASSIGNED, 1, X86_INS_SAHF, 1);
        }
        else{
            if(IS_MEMORY(to_type) || src_size==to_size){
                create_instruction(from_op, from_type, 0, UNASSIGNED, to_op, to_type, src_size, X86_INS_MOV, src_size);
            }
            else{ //there is a size conversion
                if(src_size>to_size){ //we need only part of src, just use move
                    create_instruction(from_op, from_type, 0, UNASSIGNED, to_op, to_type, to_size, X86_INS_MOV, to_size);
                }
                else if (src_size==4){ //we can't use MOVZX for 32bit to 64bit
                    create_instruction(from_op, from_type, 0, UNASSIGNED, to_op, to_type, src_size, X86_INS_MOV, src_size); //just copy as much as you can with a simple move
                }
                else{
                    create_instruction(from_op, from_type, 0, UNASSIGNED, to_op, to_type, to_size, X86_INS_MOVZX, src_size); //TODO: the size modifier should be considered during ASM generation
                }
            }
        }
    }
#if 0
        else{ //both are mem, we can't use mov;
        MAKE_EXPLICIT(dest_type);
        create_instruction(from_op,from_type,0,UNASSIGNED,0,UNASSIGNED,to_size,X86_INS_PUSH, src_size);

        MAKE_EXPLICIT(op1_type);
        create_instruction(to_op,to_type,0,UNASSIGNED,0,UNASSIGNED,to_size,X86_INS_POP, src_size);
    }
#else
    else {
        printf("just use that memory address, why would you incur the move?");
        assert(0);
    }
#endif
}

static inline void copy_parameter_n(int i, u64 param, enum shadow_type type, u16 size,u8 is_ptr) {
    u64 dest;
    switch (i) {
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
    mov_from_to(param, type, dest, GLOBAL, 8, size,is_ptr); //we always use the 8 bytes version of the dest
}

/*The two helpers will place instructions to perform the following:
 * 1. Allocate a stack space for the result
 * 2. Prepare the callee parameters
 * 3. Increment the stack pointer (parameters size)
 * 4. Call
 * 5. Decrement the stack pointer
*/
static void *callHelperTruncate(u64 operand, u16 orig_size, u16 trunc_size) {
    void *res = allocate_from_stack(8);
    //prepare the parameters
    copy_parameter_n(1, operand, MEMORY, 8, 0);
    copy_parameter_n(2, orig_size, IMMEDIATE, 8, 0); //8 so the 8 bytes destination would be used, and the rest of unused bytes would be cleared.
    copy_parameter_n(3, trunc_size, IMMEDIATE, 8, 0);
    copy_parameter_n(4, (u64) res, MEMORY, 8, 1); //this parameter is a pointer, so LEA is needed.
    //Increment the stack pointer
    create_instruction(-STACK_CURRENT_OFFSET, IMMEDIATE, R_ESP, GLOBAL,  R_ESP, GLOBAL_IMPLICIT, 8, X86_INS_ADD, 8); // current local vars plus an extra 8 bytes (eip but I could be wrong), so the callee can use the top of the stack
    //call
    create_instruction(0, UNASSIGNED, 0, UNASSIGNED, (u64) TRUNCATE_HELPER, IMMEDIATE, 2,
                       CALL_HELPER, 2); //should be a call to a relative address
    //Decrement the stack pointer
    create_instruction(-STACK_CURRENT_OFFSET, IMMEDIATE, R_ESP, GLOBAL, R_ESP, GLOBAL_IMPLICIT, 8, X86_INS_SUB, 8); // so we can use the offseteting again

    return res;
}

static void *callHelperConcat(u64 op1, u16 op1_size, u64 op2, u16 op2_size, u16 concat_size) {
    void *res = allocate_from_stack(8);
    //prepare the parameters
    copy_parameter_n(1, op1, MEMORY, 8, 0);
    copy_parameter_n(2, op1_size, IMMEDIATE, 8,0); //8 so the 8 bytes destination would be used, and the rest of unused bytes would be cleared.
    copy_parameter_n(3, op2, MEMORY, 8, 0);
    copy_parameter_n(4, op2_size, IMMEDIATE, 8, 0);
    copy_parameter_n(5, concat_size, IMMEDIATE, 8, 0);
    copy_parameter_n(6, (u64) res, MEMORY, 8, 1);
    //Increment the stack pointer
    create_instruction(-STACK_CURRENT_OFFSET, IMMEDIATE, R_ESP, GLOBAL,  R_ESP, GLOBAL_IMPLICIT, 8, X86_INS_ADD, 8); // so the callee can use the top of the stack
    //call
    create_instruction(0, UNASSIGNED, 0, UNASSIGNED, (u64) CONCAT_HELPER, IMMEDIATE, 2,
                       CALL_HELPER, 2); //should be a call to a relative address
    //Decrement the stack pointer
    create_instruction(-STACK_CURRENT_OFFSET, IMMEDIATE, R_ESP, GLOBAL, R_ESP, GLOBAL_IMPLICIT, 8, X86_INS_SUB, 8); // so we can use the offseteting again
    return res;
}

static inline int add_operands(u64 op1, enum shadow_type op1_type, asm_operand *ret, void *label, u16 size) {
    int i = 0;
    if (op1_type == MULTIPLE_OPS) {
        assert(op1 > 0);
        multiple_operands *loperands = (multiple_operands *) op1;
        for (i = 0; i < loperands->num_operands; i++) {
            ret[i] = loperands->operands[i];
        }
    } else if (op1_type == EFFECTIVE_ADDR || IS_GLOBAL(op1_type)  || op1_type == IMMEDIATE || IS_MEMORY(op1_type)) {
        if (op1_type == EFFECTIVE_ADDR) assert(op1 > 0);
        ret[i].operand = op1; //can still keep the Qemu register ID here until the instruction creation
        ret[i].type = op1_type;
        ret[i].label = label;
        ret[i].size = size;
        i++;
    }
    //else if op is implicit or unassigned, ignore
    return i;
}

static inline void
merge_ops(u64 op1, enum shadow_type op1_type, u64 op2, enum shadow_type op2_type, multiple_operands *ret, void *l1, u16 size_l1, void *l2, u16 size_l2) {
    int i, j = 0;

    i = add_operands(op1, op1_type, &(ret->operands[0]), l1, size_l1);
    j = add_operands(op2, op2_type, &(ret->operands[i]), l2, size_l2);

    ret->num_operands = i + j;
}

static inline void prep_one_operand(void *label_mem, u64 *op1, enum shadow_type op1_type, u16 size, u16 size_src){
    if (IS_MEMORY(op1_type)) { //no need to move, just use the pointer to the label effective address
         *op1 = (u64)label_mem; //op1 now points to the same memory; we avoid copying TAIN, LOAD etc. around
    } else if (IS_GLOBAL(op1_type)) { //we have to move
         mov_from_to((u64)label_mem, MEMORY, *op1, op1_type, size, size_src,0); //Note that even memory loads(Load, Taint, Concat) and Load_REG would be handled correctly this way
    }
    //else it is either IMM or not assigned
}

static inline void prep_mult_operand(u64 dest, u16 size){
    multiple_operands *multOps = (multiple_operands *)dest;
    for (int i=0;i<multOps->num_operands;i++){
        if(multOps->operands[i].label!=NULL){
            prep_one_operand(multOps->operands[i].label,&(multOps->operands[i].operand),multOps->operands[i].type,size,multOps->operands[i].size);
        }
    }
}

static inline void prepare_operand(dfsan_label label, u64 *op1, enum shadow_type op1_type,
                                   u16 size) { //move from label placeholder, instead of the operand itself
    dfsan_label_info *labelInfo = dfsan_get_label_info(label);
    u64 dest = labelInfo->instruction.dest;
    u16 dest_type = labelInfo->instruction.dest_type;
    if (dest_type == MULTIPLE_OPS || dest_type == EFFECTIVE_ADDR) {
        assert(dest > 0);
        assert(dest_type == op1_type);
        *op1 = dest; //needed for the assembly text generation
        if(dest_type == MULTIPLE_OPS) {
            prep_mult_operand(dest,size); //prep each operand; needed for the data flow propagation

        }
        else { //EFFECTIVE_ADDR
            dfsan_label_info *l1Info = dfsan_get_label_info(labelInfo->l1); //l1 is a a MULTI_OPS
            dfsan_label_info *l2Info = dfsan_get_label_info(labelInfo->l2); //l2 is a a MULTI_OPS
            prep_mult_operand((u64)l1Info->label_mem,size);
            prep_mult_operand((u64)l2Info->label_mem,size);
        }
    }
    else{
        prep_one_operand(labelInfo->label_mem, op1, op1_type, size, labelInfo->instruction.size);
    }
}

static inline void create_instruction_label(dfsan_label_info *label) {

    inst *instruction = &(label->instruction);
    assert(instruction->op!=0);
//    const char *inst=printInst(instruction);
//    printf("prepare_operand called %s\n",inst);

    prepare_operand(label->l1, &(instruction->op1), instruction->op1_type,
                    instruction->size); //move the data from l1 to op1
//    printf("prepare_operand called %s\n",inst);

    prepare_operand(label->l2, &(instruction->op2), instruction->op2_type,
                    instruction->size); //move the data from l1 to op2

    add_instruction(instruction);;
    //store the result somewhere on the stack
    label->label_mem = allocate_from_stack(instruction->size); //allocate as needed not always 8
//    printf("create_instruction_label called %s\n",inst);
    mov_from_to(instruction->dest, instruction->dest_type, (u64) label->label_mem, MEMORY,
                instruction->size, instruction->size,0); //move the result to the stack space
    //In principal, we need to label_mems. If the instruction modifies the EFLAGS, we need to store the EFLAGS in that label that would take two instructions
    //unless we assume that next instructions wouldn't mess up EFLAGS.
    //we can free the child nodes labels, but for now we just consume stack that wouldn't be a problem is the slice is not too large.
}

//TODO: still not sure if propagation for EFLAGS is done correctly
void generate_asm(int root) {
    struct dfsan_label_info *label = dfsan_get_label_info(root);
    if (label->label_mem != 0) {
        return; //we already evaluated this label, in another subtree; just use the value stored in label_mem
    }
    if(root==CONST_LABEL){
        return; //in case the root is CONST in the first place
    }
    if (label->l1 != CONST_LABEL) {
        generate_asm(label->l1);
        label->instruction.size_src = dfsan_get_label_info(label->l1)->instruction.size; //a temporary fix for size handling
    }
    if (label->l2 != CONST_LABEL) { // by appending to latest_node, we merge left and right labels)
        generate_asm(label->l2);
    }
    if (label->instruction.dest == 0 && (label->instruction.op >= op_start_id && label->instruction.op < op_end_id)) {
        switch (label->instruction.op) {
            case Load_REG:
                label->label_mem = allocate_from_stack(label->instruction.size);
                mov_from_to(label->instruction.op1, label->instruction.op1_type, (u64) label->label_mem, MEMORY,
                            label->instruction.size,label->instruction.size,0);
                label->instruction.dest = (u64) label->label_mem;
                break;
            case TAINT:
                assert(label->instruction.op1<INPUT_SIZE); //the given input at exec time has been larger than the configured size for asm generation
                label->label_mem = taints[label->instruction.op1]; //op1 is expected to have the legit offset
                label->instruction.dest = (u64) label->label_mem;
                break;
            case Load:
                label->label_mem = taints[dfsan_get_label_info(label->l1)->instruction.op1]; //op1 is expected to have the legit offset
                label->instruction.dest = (u64) label->label_mem;
                break;
            case Trunc:
                label->label_mem = callHelperTruncate((u64) dfsan_get_label_info(label->l1)->label_mem,
                                                      dfsan_get_label_info(label->l1)->instruction.size,
                                                      label->instruction.size); //what about the dest.type; probably memory
                label->instruction.dest = (u64) label->label_mem;
                break;
            case Concat: {
                dfsan_label_info *l1_label = dfsan_get_label_info(label->l1);
                dfsan_label_info *l2_label = dfsan_get_label_info(label->l2);
                label->label_mem = callHelperConcat((u64) l1_label->label_mem, l1_label->instruction.size,
                                                    (u64) l2_label->label_mem,
                                                    l2_label->instruction.size, label->instruction.size);
                label->instruction.dest = (u64) label->label_mem;
                break;
            }
            case UNION_MULTIPLE_OPS: {
                dfsan_label_info *l1_label = dfsan_get_label_info(label->l1); //we need to keep track of label_mem in multiple_operands for operands initialization
                dfsan_label_info *l2_label = dfsan_get_label_info(label->l2);
                multiple_operands *ret = (multiple_operands *) calloc(1, sizeof(multiple_operands));
                memset(ret, 0, sizeof(multiple_operands));
                merge_ops(label->instruction.op1, label->instruction.op1_type, label->instruction.op2,
                          label->instruction.op2_type, ret,l1_label->label_mem,l1_label->instruction.size,l2_label->label_mem,l2_label->instruction.size);
                assert(ret->num_operands > 0);
                label->instruction.dest = (u64) ret;
                label->label_mem = (void *)ret;
                break;
            }
                //would need register occupation because they would be immediately used; we occupy them in the caller
            case EFFECTIVE_ADDR_UNION: {
                dfsan_label_info *l1_label = dfsan_get_label_info(label->l1);//assemble the effective address based on the contract
                dfsan_label_info *l2_label = dfsan_get_label_info(label->l2);
                x86_op_mem *eff_mem = (x86_op_mem *) malloc(sizeof(x86_op_mem));
                eff_mem->index = l1_label->instruction.op1; //note that we are storing Qemu based register IDs
                eff_mem->scale = l1_label->instruction.op2;
                eff_mem->base = l2_label->instruction.op1;
                eff_mem->disp = l2_label->instruction.op2;
                label->instruction.dest = (u64) eff_mem;
                label->label_mem = (void *)eff_mem;
                break;
            }
            case Nop:
                break;
            default:
                printf("operation case is not supported!\n");
                assert(0);
        }
    } else {
        //register collision will not happen
        //before this line, the transfer between the child dest and the operand should be done; for multiple_ops and effective we need to just copy the pointer while for other types we need a mov instruction
        create_instruction_label(label);
    }
}

void generate_asm_body(int root){
    generate_asm(root);
    if(STACK_TOP!=NULL){ //return value that is that last label value
        create_instruction((u64)STACK_TOP, MEMORY, 0, UNASSIGNED, R_EAX, GLOBAL, stack_top_size, X86_INS_MOV, stack_top_size); //separate from epilogue because depends on the STACK_TOP that we don't have before hand
    }
}

void print_asm_slice_function(const char *file_name){
    int fd = open(file_name, O_RDWR|O_CREAT,0777);
    if (fd == -1){
        printf("error openning file in printing slice_function:%s\n",file_name);
        assert(0);
    }
    ftruncate(fd,0);
    //print prologue, copies the input into the local stack
    write(fd,SLICE_PROLOGUE,strlen(SLICE_PROLOGUE));
    for(inst_list *temp=instructions_head;temp!=NULL;temp=temp->next_inst){
        const char *asm_ins_txt=print_X86_instruction(temp->ins);
        if(asm_ins_txt!=NULL){
            write(fd, asm_ins_txt, strlen(asm_ins_txt));
            write(fd, "\n", 1);
            printf("%s\n",asm_ins_txt);
        }
        else{
            printf("WARNING: Instruction text for op=%d, op1=%llx, op2=%llx, dest=%llx, was %p\n",temp->ins->op, temp->ins->op1, temp->ins->op2, temp->ins->dest,asm_ins_txt);
        }
    }
    //print epilogue
    write(fd,SLICE_EPILOGUE,strlen(SLICE_EPILOGUE));
    close(fd);
}

//in order to generate the tree graph, install graphviz and run: dot -Tpng ./union_graphviz.gv -o union-sample.png

static int dfsan_graphviz_traverse(dfsan_label root, FILE *vz_fd, int i) {
    int prev_i = 0;
    if (root != CONST_LABEL) {
        dfsan_label_info *label = (dfsan_label_info *) dfsan_get_label_info(root);
        dfsan_label l1 = label->l1;
        dfsan_label l2 = label->l2;
        char *inst_name = (char *) printInst(&(label->instruction)); //GET_INST_NAME(__dfsan_label_info[i].op);
        if (inst_name != NULL) {
            fprintf(vz_fd, "n%03d [label=\"%s\"] ;\n", i, inst_name);
        } else {
            fprintf(vz_fd, "n%03d [label=\"%d\"] ;\n", i, label->instruction.op);
        }
        prev_i = i;
        if (l2 != CONST_LABEL) { //since it is the first appearing operand (in the instruction) in op2 and l2
            fprintf(vz_fd, "n%03d -- n%03d ;\n", prev_i, i + 1);
            i = dfsan_graphviz_traverse(l2, vz_fd, i + 1);
        }
        if (l1 != CONST_LABEL && l1 != l2) {
            fprintf(vz_fd, "n%03d -- n%03d ;\n", prev_i, i + 1);
            i = dfsan_graphviz_traverse(l1, vz_fd, i + 1);
        }
    }
    return i;
}

void dfsan_graphviz(dfsan_label root, char *graph_file) {
    printf("INFO: SE: root=%d\n", root);
    printf("INFO: SE: creating graph file to %s, install graphviz and run dot for visualization\n", graph_file);
    FILE *vz_fd = fopen(graph_file, "w+");
    assert(vz_fd != NULL);
    fprintf(vz_fd, "%s \"\"\n{\n%s cluster%02d\n{\nn%03d ;\n", "graph", "subgraph", 1, 2);
    dfsan_graphviz_traverse(root, vz_fd, 2);
    fprintf(vz_fd, "}\n}\n");
    fclose(vz_fd);
}