#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define OB_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)calloc(1024, 4);
	printf("calloc address = %08x\n", a);


#ifdef	OB_TEST	

	a[-1] = 1;
	a[1024] = 1;

#endif

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        free(a);

        return 0;
}
