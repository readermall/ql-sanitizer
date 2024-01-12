#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UINIT_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)malloc(1024);
	printf("malloc address = %08x\n", a);

	unsigned char *b = (unsigned char *)realloc(a, 2048);
        printf("realloc address = %08x\n", b);

	b[0] = 100;
	printf("%02x\n", b[0]);
        
#ifdef	UINIT_TEST

	for(int i = 0; i  < 1024; i++)
		printf("%02x", b[i]);
	printf("\n");

#endif	

        free(b);

        return 0;
}
