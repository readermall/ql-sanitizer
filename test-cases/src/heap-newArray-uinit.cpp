#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UINIT_TEST

int main(void)
{
        unsigned char *a = new unsigned char [1024];
	printf("new array address = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);
        
#ifdef	UINIT_TEST

	for(int i = 0; i  < 1024; i++)
		printf("%02x", a[i]);
	printf("\n");

#endif	

        delete[] a;

        return 0;
}
