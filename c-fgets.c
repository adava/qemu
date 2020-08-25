// C program to illustrate 
// fgets() 
#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#define MAX 15 
int main() 
{ 
    int a=95;
    int i=0;
    char buf[MAX];
    char buf2[MAX];
    int b=96;
    fgets(buf, MAX, stdin); 
    printf("a=%d, b=%d \t buf %p: %s\n", a, b, buf, buf);
    buf2[0] = buf[0];
    buf2[1] = '\0';
    i=atoi(buf2);
    //strcpy(buf2,buf);
//    printf("buf2 at %p, i=%d\n", buf2, i);
    return 0; 
}
