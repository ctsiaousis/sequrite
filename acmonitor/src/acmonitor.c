#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utils.h>
#include <regex.h>

#define ENTRY_ELEMENTS 7

typedef struct myTime {

	int hour;
	int minute;
	int second;

}myT;

typedef struct myDate {

	int day;
	int month;
	int year;

}myD;

typedef struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	myD* date; /* file access date */
	myT* time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */
}ENT;

void usage(void);
void countLines(char*, int, size_t*);
void list_unauthorized_accesses(FILE *log);
void list_file_modifications(FILE *log, char *file_to_scan);
myD* createDate(char*);
myT* createTime(char*);
ENT* createEntry(char**);
ENT** populateLogs(FILE *, size_t*);



int main(int argc, char *argv[]){
	int ch;
	FILE *log;
	if (argc < 2)
		usage();

	char* log_path = "/tmp/file_logging.log";
	log = fopen(log_path, "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", log_path);
		return 1;
	}

	size_t entries_size; 
	ENT **myEntries = populateLogs(log, &entries_size);
	printf("i have %zu entries",entries_size);
	// size_t i;
	// for(i = 0; i < entries_size; i+=10){
	// 	printf("\n%s\n",myEntries[i]->file);
	// 	printf("\n%s\n",myEntries[i]->fingerprint);
	// 	printf("\n%d\n",myEntries[i]->uid);
	// 	printf("\n%d\n",myEntries[i]->date->day);
	// 	printf("\n%d\n",myEntries[i]->date->month);
	// 	printf("\n%d\n",myEntries[i]->date->year);
	// 	printf("\n%d\n",myEntries[i]->time->hour);
	// 	printf("\n%d\n",myEntries[i]->time->minute);
	// 	printf("\n%d\n",myEntries[i]->time->second);
	// 	printf("\n%d\n",myEntries[i]->action_denied);
	// 	printf("\n%d\n",myEntries[i]->access_type);
	// }

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./acmonitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void countLines(char *bash_cmd, int buffer_len, size_t *ret){
	char *buffer = (char *)malloc(buffer_len+1);
	FILE *pipe;

	// printf("BASHCMD: %s\n",bash_cmd);
	pipe = popen(bash_cmd, "r");

	if (NULL == pipe) {
	    perror("pipe");
	    exit(1);
	}

	fread(buffer, buffer_len, sizeof(char), pipe);

	buffer[buffer_len] = '\0'; 

	pclose(pipe);

	sscanf(buffer, "%zu", ret);
	free(buffer);
	return;
}


void list_unauthorized_accesses(FILE *log)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

}


void list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

}

myD* createDate(char* value){
	int day, month, year;

	char *line = strtok(strdup(value), "/");
	sscanf(line,"%d",&day);

	line = strtok(NULL, "/");
	sscanf(line,"%d",&month);

	line = strtok(NULL, "/");
	sscanf(line,"%d",&year);

	myD* ret_date = malloc(sizeof(myD));
	ret_date->day = day;
	ret_date->month = month;
	ret_date->year = year;
	return ret_date;
}

myT* createTime(char* value){
	int hour, minute, second;

	char *line = strtok(strdup(value), ":");
	sscanf(line,"%d",&hour);

	line = strtok(NULL, ":");
	sscanf(line,"%d",&minute);

	line = strtok(NULL, ":");
	sscanf(line,"%d",&second);

	myT* ret_time = malloc(sizeof(myD));
	ret_time->hour = hour;
	ret_time->minute = minute;
	ret_time->second = second;
	return ret_time;
}

ENT* createEntry(char* values[ENTRY_ELEMENTS]){
	ENT* my_entry = malloc(sizeof(ENT));
	
	my_entry->file = strdup(values[0]);

	sscanf(values[1],"%d", &my_entry->uid);

	myD* d = createDate(values[2]);
	my_entry->date = d;

	myT* t = createTime(values[3]);
	my_entry->time = t;

	sscanf(values[4],"%d", &my_entry->access_type);

	my_entry->fingerprint = strdup(values[5]);

	sscanf(values[6],"%d", &my_entry->action_denied);

	return my_entry;
}

ENT** populateLogs(FILE *log, size_t* entries_size){
	char *buffer;
    size_t filelen;
    fseek(log, 0, SEEK_END);          // Jump to the end of the file
    filelen = ftell(log);             // Get the current byte offset in the file
    rewind(log);                      // Jump back to the beginning of the file
  
    buffer = (char *)malloc((filelen + 1) * sizeof(char));
	fread(buffer, filelen, 1, log); // Read in the entire file
    if( filelen == 0){
        buffer[0] = '\0';
    }
	// printf("%s\n\n",buffer);

	size_t log_lines;
	countLines("wc -l < /tmp/file_logging.log", 32, &log_lines);
    printf("\n\nLOGLINES: %zu\n",log_lines);

	ENT** entries = malloc(sizeof(ENT*)*(log_lines/(ENTRY_ELEMENTS+2)));
	size_t line_counter = 0;
	size_t entry_counter = 0;
	char *line_pointer = strdup(buffer);
	char *line = strsep(&line_pointer, "\n");

    regex_t regex;
    int reg_val, i;
	char *mValue[ENTRY_ELEMENTS] = {"","","","","","",""};
	
	while(line) {
    	reg_val = regcomp(&regex,"Start",0); //set up regular expression
		reg_val = regexec(&regex, line, 0, NULL, 0); //to check if line contains "Start"

		if(reg_val == 0){ //new entry
		 	//line++
   			line = strsep(&line_pointer, "\n");

			for(i = 0; i < ENTRY_ELEMENTS; i++){
				mValue[i] = (strchr(line,'>')+2);
				//line++
   				line  = strsep(&line_pointer, "\n");
			}
			entries[entry_counter] = createEntry(mValue);
			entry_counter += 1;
		}
		//line++
   		line  = strsep(&line_pointer, "\n");
	}

	*entries_size = entry_counter;

	free(buffer);
	free(line_pointer); //strdup returnes malloced string
    return entries;
}
