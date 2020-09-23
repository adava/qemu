//
// Created by sina on 5/14/20.
//

#ifndef TAINT_UTILITY_H
#define TAINT_UTILITY_H

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
    R_HIGH = 15,
    R_AL = 0,
    R_CL = 1,
    R_DL = 2,
    R_BL = 3,
    R_AH = 16, //from here, they are different than i386/cpu.h
    R_CH = 17,
    R_DH = 18,
    R_BH = 19,
    R_EXTRA = 20,
    R_EIP = 21,
    R_SEGS = 22,
    R_ES = 23,
    R_CS = 24,
    R_SS = 25,
    R_DS = 26,
    R_FS = 27,
    R_GS = 28,
    R_OTHERS
};

int size_map[] = {0,0,1,2,2,3,3,3,3}; //mapping 1,2,4,8 to their indexes

const char *qemu_regs_to_size_map[R_HIGH+1][4] = {
    {"al","ax","eax","rax"},// R_EAX = 0,
    {"cl","cx","ecx","rcx"},//R_ECX = 1,
    {"dl","dx","edx","rdx"},//R_EDX = 2,
    {"bl","bx","ebx","rbx"},//R_EBX = 3,
    {"spl","sp","esp","rsp"},//R_ESP = 4,
    {"bpl","bp","ebp","rbp"},//R_EBP = 5,
    {"sil","si","esi","rsi"},//R_ESI = 6,
    {"dil","di","edi","rdi"},//R_EDI = 7,
    {"r8b","r8w","r8d","r8"},//R_R8 = 8,
    {"r9b","r9w","r9d","r9"},//R_R9 = 9,
    {"r10b","r10w","r10d","r10"},//R_R10 = 10,
    {"r11b","r11w","r11d","r11"},//R_R11 = 11,
    {"r12b","r12w","r12d","r12"},//R_R12 = 12,
    {"r13b","r13w","r13d","r13"},//R_R13 = 13,
    {"r14b","r14w","r14d","r14"},//R_R14 = 14,
    {"r15b","r15w","r15d","r15"},//R_R15 = 15,
};
#endif //QEMU_UTILITY_H
