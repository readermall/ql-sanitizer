#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define OOB_TEST

int main(void)
{
        unsigned int *a = new unsigned int;
	printf("new address = %08x\n", a);

#ifdef	OOB_TEST

	printf("%02x\n", a[-1]);
	printf("%02x\n", a[1024]);

#endif

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        delete a;

        return 0;
}
