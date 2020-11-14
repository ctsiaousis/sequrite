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
void list_unauthorized_accesses(ENT **, size_t);
void list_file_modifications(ENT **, size_t , char *);
myD* createDate(char*);
myT* createTime(char*);
ENT* createEntry(char**);
ENT** populateLogs(FILE *, size_t*);
int get_pwd_path(char* argv_0,char*);



int main(int argc, char *argv[]){
	int ch;
	FILE *log;
	if (argc < 2)
		usage();
	
    // char *pwd_path = malloc(0xFFF);
	// int pwd_path_len = get_pwd_path(argv[0],pwd_path);
	// printf("PWD\"%s\"\n", pwd_path);
	// strcat(pwd_path, "/another.log");

	char* log_path = "/tmp/file_logging.log";
	log = fopen(log_path, "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", log_path);
		return 1;
	}

	size_t entries_size; 
	ENT **myEntries = populateLogs(log, &entries_size);
	printf("i have %zu entries",entries_size);

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(myEntries, entries_size, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(myEntries, entries_size);
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


void list_unauthorized_accesses(ENT ** entries, size_t en_size){
	size_t i, j;
	int exists;
	int malUsrs[en_size][2];
	int distinctUsrs = 0;

	for(i = 0; i < en_size; i++){
		if(entries[i]->action_denied == 1){

			for(j = 0; j < distinctUsrs; j++){
				if(malUsrs[j][0] == entries[i]->uid ){
					malUsrs[j][1]++;
					exists = 1;
					break;
				}
			}

			if(!exists){
				malUsrs[distinctUsrs][0] = entries[i]->uid;
				malUsrs[distinctUsrs][1] = 1; //first atempt
				distinctUsrs++;
			}
			exists = 0; //for next iteration
		}
	}

	printf("\n UID \t|\t ATTEMPTS\n");
	for(i = 0; i < distinctUsrs; i++){
		printf(" %d \t|\t %d\n",malUsrs[i][0], malUsrs[i][1]);
	}
	return;

}


void list_file_modifications(ENT ** entries, size_t en_size, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

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
	// printf("TST: %s",buffer);
	sscanf(buffer, "%zu", ret);
	free(buffer);
	return;
}

/*
 * Reads the logfile, and parses it. Creates entries
 * and returns them as an entry table.
 *
 */
ENT** populateLogs(FILE *log, size_t* entries_size){
	char *buffer;
    size_t filelen;
    fseek(log, 0, SEEK_END);
    filelen = ftell(log);
    rewind(log);
	/* Read whole file, save it to buffer */
    buffer = (char *)malloc((filelen + 1) * sizeof(char));
	fread(buffer, filelen, 1, log);
    if( filelen == 0){
        buffer[0] = '\0';
    }
	/* Exec in shell "wc -l < logfile" */
	size_t log_lines;
	countLines("wc -l < /tmp/file_logging.log", 32, &log_lines);
    printf("\n\nLOGLINES: %zu\n",log_lines);
	/* Allocate entry table and prepare to parse buffer */
	ENT** entries = malloc(sizeof(ENT*)*(log_lines/(ENTRY_ELEMENTS+2)));
	size_t line_counter = 0;
	size_t entry_counter = 0;
    regex_t regex;
    int reg_val, i;
	char *mValue[ENTRY_ELEMENTS] = {"","","","","","",""};

	/* 
	 * just to be safe, duplicate the buffer to another pointer.
	 * it is now easier to use buffer in parallel if needed.
	 */
	char *line_pointer = strdup(buffer);
	char *line = strsep(&line_pointer, "\n");
	
	while(line) {
		//set up regular expression
		//to check if line contains "Start"
    	reg_val = regcomp(&regex,"Start",0);
		reg_val = regexec(&regex, line, 0, NULL, 0);

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

/* Note that argv[0] should be passed */
int get_pwd_path(char* argv_0,char *pwd_path){
	ssize_t r = readlink("/proc/self/exe", pwd_path, 0xFFF);
	if (r < 0) {
        perror("read link error: ");
		pwd_path = NULL;
        return -1;
    }
	int exe_name_len = strlen(argv_0+2);
	int pwd_path_len = strlen(pwd_path) - exe_name_len - 1;
	pwd_path[pwd_path_len] = '\0';
	return pwd_path_len;
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
