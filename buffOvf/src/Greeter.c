#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>



unsigned pagesize = 4096;
#define PAGE_START(P) ((unsigned)(P) & ~(pagesize-1))
#define PAGE_END(P)   (((unsigned)(P) + pagesize - 1) & ~(pagesize-1))

unsigned char Name[1024];

void readString() {
	char buf[32];
	int i;

	gets(buf);

	for (i=0; i<128; i++)
       		Name[i] = buf[i];

   	return;
}



int main(void) {

	mprotect((void *)PAGE_START(Name), PAGE_END(Name+1024) - PAGE_START(Name),
         	 PROT_READ|PROT_WRITE|PROT_EXEC);

	printf("What is your name?\n");
	readString();
	printf("Hello %s, have a nice day.\n", Name);
	
	exit(0);
}
