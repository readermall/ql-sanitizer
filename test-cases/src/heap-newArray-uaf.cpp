#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UAF_TEST

int main(void)
{
        unsigned char *a = new unsigned char [1024];
	printf("new array address = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        delete[] a;

#ifdef	UAF_TEST

	a[0] = 1;
	printf("%02x\n", a[0]);

#endif
	return 0;
}
