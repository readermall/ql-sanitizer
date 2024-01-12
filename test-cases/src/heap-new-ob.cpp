#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define OB_TEST

int main(void)
{
        unsigned int *a = new unsigned int;
	printf("new address = %08x\n", a);


#ifdef	OB_TEST	

	a[-1] = 1;
	a[1024] = 1;

#endif

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        delete a;

        return 0;
}
