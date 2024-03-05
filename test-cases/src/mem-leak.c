#include <stdio.h>
#include <stdlib.h>

void GetMemory(char *p, int num)
{
    p = (char*)malloc(sizeof(char) * num);
    
}
 
int main(int argc,char** argv)
{
    char *str = NULL;
    GetMemory(str, 100);
    
    return 0;
}