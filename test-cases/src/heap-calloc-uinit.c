#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UINIT_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)calloc(1024, 4);
	printf("calloc address = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);
        
#ifdef	UINIT_TEST

	for(int i = 0; i  < 1024; i++)
		printf("%02x", a[i]);
	printf("\n");

#endif	

        free(a);

        return 0;
}
