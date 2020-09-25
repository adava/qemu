#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#define ABBRV_SIZE 4

char abbrv[ABBRV_SIZE]={'K', 'M', 'G', 'T'};

long int index_abbrv(char c){
    for(int i=0;i<ABBRV_SIZE;i++){
        if (abbrv[i]==c){
            return i;
        }
    }
    return -1;
}
int main(int argc, char **argv){
    char b;
    long int num=0;
    int index=-1;
    int p=0;
    int d=0;
    long int conv_size = 0;
    if(argc>1){
        printf("ERROR: this program does not take an argument!\n");
        return 0;
    }
    scanf("%c",&b);
    index = index_abbrv(b);
    if(index<=-1){
        printf("ERROR: only K, M, G and T are allowed!\n");
        return 0;
    }
    else{
        p = 10 * (index+1);
        scanf("%lu",&num);
    }
    d = 1 << p;
    conv_size = num/d;
//    printf("The size is %.2lu%C\n",conv_size,b);
    return 0;
}