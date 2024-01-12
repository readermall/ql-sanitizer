/*
#
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# 2023-12-19
# Author: readermall and liuyi
#
#
*/

#include <stdio.h>
#include <string.h>

int print(char *src){
	char buf[2];
        strcpy(buf,src);
	return 3;
}

int main(int argc, char* argv[]) {
        char buf[256]="11222222222222222222222";
        print(buf);
        return 0;
}
