#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define OB_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)malloc(1024);
	printf("malloc address = %08x\n", a);

	unsigned char *b = (unsigned char *)realloc(a, 2048);
        printf("realloc address = %08x\n", b);

#ifdef	OB_TEST	

	b[-1] = 1;
	b[1024] = 1;

#endif

	b[0] = 100;
	printf("%02x\n", b[0]);
        
        free(b);

        return 0;
}
