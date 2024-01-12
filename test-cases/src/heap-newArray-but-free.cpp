#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define NEWARRAY_BUT_FREE

int main(void)
{
	unsigned char *a = new unsigned char [1024];
	
	printf("new array address = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);

#ifdef	NEWARRAY_BUT_FREE

	free(a);

#endif

	delete[] a;

        return 0;
}
