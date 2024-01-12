#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UAF_TEST

int main(void)
{
        unsigned int *a = new unsigned int;
	printf("malloc address = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        delete a;

#ifdef	UAF_TEST

	a[0] = 1;
	printf("%02x\n", a[0]);

#endif
	return 0;
}
