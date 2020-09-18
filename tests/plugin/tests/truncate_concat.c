#include <stdio.h>
#include <string.h>
#include <stdlib.h>
//
// Created by sina on 2020-09-17.
//
void trunc_func(long long unsigned int op,short unsigned int orig_size,short unsigned int trunc_size,void *retaddr){
    long long unsigned int t1=(op << (8-trunc_size)*8);
    long long unsigned int ret= t1 >> (8-trunc_size)*8; //this + the previous line throws away the bytes we don't need
    switch (orig_size){
        case 1:
            *((char *)retaddr) = (char)ret;
            break;
        case 2:
            *(short int *)retaddr = (short int)ret;
            break;
        case 4:
            *(unsigned int *)retaddr = (unsigned int)ret;
            break;
        case 8:
            *(long long int *)retaddr = ret;
            break;
        default:
            break;
    }
}


void concat_func(long long unsigned int op1,short unsigned int op1_size,long long unsigned int op2,short unsigned int op2_size,short unsigned int concat_size,void *retaddr){

    long long unsigned int t2= (op2<<(op1_size)*8); //prepares op2 for concatenation
    long long unsigned int ret = op1 | t2; //concat
    switch (concat_size){
            case 1:
            *((char *)retaddr) = (char)ret;
                break;
            case 2:
                *(short int *)retaddr = (short int)ret;
                break;
            case 4:
                *(unsigned int *)retaddr = (unsigned int)ret;
                break;
            case 8:
                *(long long int *)retaddr = ret;
                break;
            default:
               break;
    }
}

void main(){
    //testing concat
    long long unsigned int new_op=0;
    long long unsigned int op1 = 0xf000bc;
    long long unsigned int op2 = 0xdb00;
    concat_func(0xf000bc,4,0xdb00,2,8,(void *)&new_op);
    printf("concating 4 bytes of 0x%llx with 2 bytes of 0x%llx => new_op=%llx\n",op1,op2,new_op);
    //testing truncate
    new_op = 0;
    trunc_func(op1,4,2,(void *)&new_op);
    printf("truncating 4 bytes of 0x%llx to 2 bytes => new_op=%llx\n",op1,new_op);

}