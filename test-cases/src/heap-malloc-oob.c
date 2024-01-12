#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define OOB_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)malloc(1024);
	if(sizeof(a) == 8){
                printf("malloc address = %0llx\n", a);
        }
        else{
                printf("malloc address = %0lx\n", a);
        }

#ifdef	OOB_TEST

	printf("%02x\n", a[-1]);
	printf("%02x\n", a[1024]);

#endif

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        free(a);

        return 0;
}
