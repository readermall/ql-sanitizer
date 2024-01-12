#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define DF_TEST

int main(void)
{
        unsigned char *a = new unsigned char[1024];
	printf("new array ddress = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        delete[] a;

#ifdef	DF_TEST

	delete[] a;

#endif
        return 0;
}
