#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UINIT_TEST

int main(void)
{
        unsigned int *a = new unsigned int;
	printf("new address = %08x\n", a);


        
#ifdef	UINIT_TEST

	printf("%08x\n", a[0]);

#endif	

        delete a;

        return 0;
}
