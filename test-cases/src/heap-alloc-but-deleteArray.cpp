#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define ALLOC_BUT_DELETEARRAY

int main(void)
{
        unsigned char *a = (unsigned char *)malloc(1024);
	printf("malloc address = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);
       
#ifdef	ALLOC_BUT_DELETEARRAY

	delete[] a;

#endif	

        free(a);

        return 0;
}
