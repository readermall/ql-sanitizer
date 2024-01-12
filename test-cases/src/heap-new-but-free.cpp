#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define NEW_BUT_FREE

int main(void)
{
        unsigned int *a = new unsigned int;
	
	printf("new address = %08x\n", a);

	a[0] = 100;
	printf("%02x\n", a[0]);

#ifdef	NEW_BUT_FREE

	free(a);

#endif

	delete a;

        return 0;
}
