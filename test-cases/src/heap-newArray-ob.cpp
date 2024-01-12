#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define OB_TEST

int main(void)
{
        unsigned char *a = new unsigned char [1024];
	printf("new array address = %08x\n", a);


#ifdef	OB_TEST	

	a[-1] = 1;
	a[1024] = 1;

#endif

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        delete[] a;

        return 0;
}
