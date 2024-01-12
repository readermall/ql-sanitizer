#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define UINIT_TEST

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
        
#ifdef	UINIT_TEST

	for(int i = 0; i  < 1024; i++)
		printf("%02x", a[i]);
	printf("\n");

#endif	

        free(a);

        return 0;
}
