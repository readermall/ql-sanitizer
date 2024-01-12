#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define OOB_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)malloc(1024);
	printf("malloc address = %08x\n", a);

        unsigned char *b = (unsigned char *)realloc(a, 2048);
        printf("realloc address = %08x\n", b);

#ifdef	OOB_TEST

	printf("%02x\n", b[-1]);
	printf("%02x\n", b[1024]);

#endif

	b[0] = 100;
	printf("%02x\n", b[0]);
        
        free(b);

        return 0;
}
