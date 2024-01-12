#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define OB_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)malloc(1024);
	if(sizeof(a) == 8){
                printf("malloc address = %0llx\n", a);
        }
        else{
                printf("malloc address = %0lx\n", a);
        }

#ifdef	OB_TEST	

	a[-1] = 1;
	a[1024] = 1;

#endif

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        free(a);

        return 0;
}
