#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UAF_TEST

int main(void)
{
        unsigned char *a = (unsigned char *)malloc(1024);
	if(sizeof(a) == 8){
                printf("malloc address = %0llx\n", a);
        }
        else{
                printf("malloc address = %0lx\n", a);
        }

	a[0] = 100;
	printf("%02x\n", a[0]);
        
        free(a);

#ifdef	UAF_TEST

	a[0] = 1;
	printf("%02x\n", a[0]);

#endif
	return 0;
}
