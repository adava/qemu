//
// Created by sina on 4/29/20.
//
#include <capstone.h>

#define INVALID_REGISTER X86_REG_ENDING+1
#define MAP_X86_REGISTER(CAP_ID) x86_regs_mapping[CAP_ID]

static uint32_t x86_regs_mapping[X86_REG_ENDING] = {INVALID_REGISTER};
void init_register_mapping(void);

enum {
    R_EAX = 0,
    R_ECX = 1,
    R_EDX = 2,
    R_EBX = 3,
    R_ESP = 4,
    R_EBP = 5,
    R_ESI = 6,
    R_EDI = 7,
    R_R8 = 8,
    R_R9 = 9,
    R_R10 = 10,
    R_R11 = 11,
    R_R12 = 12,
    R_R13 = 13,
    R_R14 = 14,
    R_R15 = 15,

    R_AL = 0,
    R_CL = 1,
    R_DL = 2,
    R_BL = 3,
    R_AH = 16, //from here, they are different than i386/cpu.h
    R_CH = 17,
    R_DH = 18,
    R_BH = 19,
};

#define NUM_MAPPED_REGISTERS 45
const uint32_t caps_x86_regs[NUM_MAPPED_REGISTERS] = {
        X86_REG_AH, // R_AH
        X86_REG_AL, //R_AL
        X86_REG_AX, //R_EAX
        X86_REG_BH, //R_BH
        X86_REG_BL, //R_BL
        X86_REG_BP, //R_EBP
        X86_REG_BPL, //R_EBP
        X86_REG_BX, //R_EBX
        X86_REG_CH, //R_CH
        X86_REG_CL, //R_CL
        X86_REG_CX, //R_ECX
        X86_REG_DH, //R_DH
        X86_REG_DI, //R_EDI
        X86_REG_DIL, //R_EDI
        X86_REG_DL, //R_DL
        X86_REG_DX, //R_EDX
        X86_REG_EAX, //R_EAX
        X86_REG_EBP, //R_EBP
        X86_REG_EBX, //R_EBX
        X86_REG_ECX, //R_ECX
        X86_REG_EDI, //R_EDI
        X86_REG_EDX, //R_EDX
        X86_REG_ES, //R_ESI
        X86_REG_ESI, //R_ESI
        X86_REG_ESP, //R_ESP
        X86_REG_RAX, //R_EAX
        X86_REG_RBP, //R_EBP
        X86_REG_RBX, //R_EBX
        X86_REG_RCX, //R_ECX
        X86_REG_RDI, //R_EDI
        X86_REG_RDX, //R_EDX
        X86_REG_RSI, //R_ESI
        X86_REG_RSP, //R_ESP
        X86_REG_SI, //R_ESI
        X86_REG_SIL, //R_ESI
        X86_REG_SP, //R_ESP
        X86_REG_SPL, //R_ESP
        X86_REG_R8, //R_R8
        X86_REG_R9, //R_R9
        X86_REG_R10, //R_R10
        X86_REG_R11, //R_R11
        X86_REG_R12, //R_R12
        X86_REG_R13, //R_R13
        X86_REG_R14, //R_R14
        X86_REG_R15, //R_R15
};

const uint32_t qemu_x86_regs[NUM_MAPPED_REGISTERS] = {
        R_AH,
        R_AL,
        R_EAX,
        R_BH,
        R_BL,
        R_EBP,
        R_EBP,
        R_EBX,
        R_CH,
        R_CL,
        R_ECX,
        R_DH,
        R_EDI,
        R_EDI,
        R_DL,
        R_EDX,
        R_EAX,
        R_EBP,
        R_EBX,
        R_ECX,
        R_EDI,
        R_EDX,
        R_ESI,
        R_ESI,
        R_ESP,
        R_EAX,
        R_EBP,
        R_EBX,
        R_ECX,
        R_EDI,
        R_EDX,
        R_ESI,
        R_ESP,
        R_ESI,
        R_ESI,
        R_ESP,
        R_ESP,
        R_R8,
        R_R9,
        R_R10,
        R_R11,
        R_R12,
        R_R13,
        R_R14,
        R_R15,
};

void init_register_mapping(void){
    for (int i=0;i<NUM_MAPPED_REGISTERS;i++){
//        printf("cap reg=%d -> qemu reg=%d\n",caps_x86_regs[i],qemu_x86_regs[i]);
        x86_regs_mapping[caps_x86_regs[i]] = qemu_x86_regs[i];
    }
//    for (int i=0;i<X86_REG_ENDING;i++){
//        printf("i=%d -> reg=%d\n",i,x86_regs_mapping[i]);
//    }
}

static char *get_type(char* op){
    int i = 0;
    while (op[i++]==' ');
    char *operand = &op[i-1];
    switch(operand[0]){
        case '$':
            return strdup("imm");
        case '%':
            return strdup("reg");
        default:
            return strdup("mem");
    }
}

static inline void print_ops(char *i_dis){
    int i = 0;
    char *ops[3];
    char *ins_copy = strdup(i_dis);
    char* token = strtok(ins_copy, " ");

    // Keep separating tokens
    while (token != NULL && i<3) {
        ops[i++] = token;
        //printf("%s\n", token);
        token = strtok(NULL, ",");
    }
    //print somehow

    g_autofree gchar *d_str;
    switch(i){
        case 1:
            d_str = g_strdup_printf("opcode: %s\n", ops[0]);
            break;
        case 2:
            d_str = g_strdup_printf("opcode: %s, op1: %s \n", ops[0], get_type(ops[1]));
            break;
        case 3:
            d_str = g_strdup_printf("opcode: %s, op1: %s (%s), op2: %s (%s)\n", ops[0], ops[1], get_type(ops[1]), ops[2], get_type(ops[2]));
            break;
        default:
            g_assert_not_reached();
    }
    qemu_plugin_outs(d_str);
}

static inline void print_id_groups(cs_insn *cs_ptr){
    g_autoptr(GString) cs_str=g_string_new("cs_insn: ");
    g_string_append_printf(cs_str,"ptr=%p, id=%u, cmd=%s\t groups=%u", (void *)cs_ptr,cs_ptr->id,cs_ptr->mnemonic,cs_ptr->detail->groups_count);
    if(cs_ptr->detail->groups_count>0){
        g_string_append_printf(cs_str,", groups[0]=%u\n",cs_ptr->detail->groups[0]);
    }
    else{
        g_string_append_printf(cs_str,"\n");
    }

    qemu_plugin_outs(cs_str->str);
}