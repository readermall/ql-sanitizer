#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UAF_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)calloc(1024, 4);
	printf("calloc address = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        free(a);

#ifdef	UAF_TEST

	a[0] = 1;
	printf("%02x\n", a[0]);

#endif
	return 0;
}
