#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) 
{
	if(argc < 2)
		return -1;
	int i;
	size_t bytes;
	FILE *file;
	int numOfFiles;
	sscanf(argv[1],"%d",&numOfFiles);
	char filename[16];

	for (i = 0; i < numOfFiles; i++) {
		sprintf(filename,"file_%d.txt", i);
		file = fopen(filename, "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filename, strlen(filename), 1, file);
			fclose(file);
		}
	}

}
