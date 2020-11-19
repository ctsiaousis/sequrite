#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */

	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	char *mode = "0040";
	int m;

/* Some tests in on GROUP permissions */
	for (i = 0; i < 10; i++) {
    	m = strtol(mode, 0, 8);
		if (chmod (filenames[i],m) < 0){
			perror("CHMOD");
        	exit(1);
    	}
	}
	/*This will raise a flag*/
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "rw");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}
	/*This will not*/
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fclose(file);
		}
	}
	/*This will raise a flag*/
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "a");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	mode = "0000";
	for (i = 0; i < 10; i++) {
    	m = strtol(mode, 0, 8);
		if (chmod (filenames[i],m) < 0){
			perror("CHMOD");
        	exit(1);
    	}
	}
	/*This will raise a flag*/
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fclose(file);
		}
	}

	mode = "0666";
	for (i = 0; i < 10; i++) {
    	m = strtol(mode, 0, 8);
		if (chmod (filenames[i],m) < 0){
			perror("CHMOD");
        	exit(1);
    	}
	}
	/*This will not*/
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			fclose(file);
		}
	}

	for (i = 0; i < 10; i++) {
    	m = strtol(mode, 0, 8);
		if (chmod (filenames[i],m) < 0){
			perror("CHMOD");
        	exit(1);
    	}
	}

	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "a+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

/* Some tests in excisting root files */
	file = fopen("/etc/os-release", "r");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		fclose(file);
	}

	file = fopen("/etc/shadow", "r");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		fclose(file);
	}

	file = fopen("/etc/test", "w+");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
		fclose(file);
	}

}
