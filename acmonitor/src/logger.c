#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <openssl/md5.h>
#include <sys/stat.h>
#include <sys/acl.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include "util.h"

char *logPath = "./file_logging.log";


size_t fwrite(const void *, size_t, size_t, FILE *);
FILE *fopen(const char *, const char *);
int checkPermissions(uid_t, gid_t, struct stat, const char *, const char *);
int appendEntryToLogfile(char*, size_t, char *, uid_t, time_t, int, int);
char* createFileFingerprint(char *, size_t, time_t);
char* executeMD5(char *, size_t, int*);
char* getAbsPath(FILE *);
void createLogFile();
char *readFile(FILE *, size_t *sze);
int fileExists(char *);



FILE *fopen(const char *path, const char *mode) 
{
	int access = 0, flag = 0;
	if( fileExists((char*)path) ){
		access = 1;
	}
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/* add your code here */
	uid_t userID =  getuid();
	time_t T= time(NULL);

	/* Get file STATS */
    struct stat sb;
    if (stat(realpath(path, NULL), &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    /* Check permissions */
    char octal_mode[6];
    sprintf(octal_mode,"%lo",(unsigned long)sb.st_mode);
    printf("OCTAL: %s\t%c\t%c\n",octal_mode,mode[0],mode[1]);
    flag = checkPermissions(userID, getegid(), sb, octal_mode, mode);

    size_t  cont_len  = 0;
    char*   file_cont = "";
    file_cont = (access == 0 || flag == 1 || original_fopen_ret == NULL)
                ?"":readFile(original_fopen_ret, &cont_len);
    
    
    /* Create log if not exists, and apend entry to it */
	createLogFile();
	appendEntryToLogfile(file_cont, cont_len, realpath(path,NULL), userID, T, access, flag);

    if (access == 1 && flag == 0 && original_fopen_ret != NULL) {
        free(file_cont);
    }
	return original_fopen_ret;
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	int access = 2, flag = 0;
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* Get UID time and filePath */
	uid_t userID  =  getuid();
	time_t T= time(NULL);
    char *absPath = getAbsPath(stream);

	/* Get file STATS */
    struct stat sb;
    if (stat(absPath, &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }
    char octal_mode[6];
    sprintf(octal_mode,"%lo",(unsigned long)sb.st_mode);
    flag = checkPermissions(userID, getegid(), sb, octal_mode, "w");
    size_t  cont_len  = 0;
    char*   file_cont = "";

    file_cont = (flag == 1)?"":readFile(stream, &cont_len);

    /* Create log if not exists, and apend entry to it */
	createLogFile();
	appendEntryToLogfile(file_cont, cont_len, absPath, userID, T, access, flag);

    if(!flag){
        free(file_cont);
        /* call the original fwrite function */
	    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	    original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
    }
    free(absPath);
	return original_fwrite_ret;
}

int appendEntryToLogfile(char*contents, size_t cont_len, char *absPath, uid_t userID, time_t T,int access,int flag){
    struct  tm tm = *localtime(&T);
    char* fingerPrint = createFileFingerprint(contents, cont_len, T);
    int i;

    char s[64], fN[256], uI[64], d[64], t[64], ac[64], fP[128], af[64], e[64];
    sprintf(s,"# ---------------- Entry Start ----------------\n");
    sprintf(fN,"filename -> %s\n", absPath);
	sprintf(uI,"userID -> %d\n",userID);
    sprintf(d,"Date -> %02d/%02d/%04d\n",tm.tm_mday, tm.tm_mon+1, tm.tm_year+1900);
    sprintf(t,"Time -> %02d:%02d:%02d\n",tm.tm_hour, tm.tm_min, tm.tm_sec);
    sprintf(ac,"Access -> %d\n",access);
    sprintf(fP,"Fingerprint -> ");
    for(i = 0; i < MD5_DIGEST_LENGTH; i++){
        sprintf(fP+strlen(fP),"%x ",(unsigned char)fingerPrint[i]);
    }
    sprintf(af,"\nActionFlag -> %d\n",flag);
    sprintf(e,"# ----------------- Entry End -----------------\n");

    char entry[0xFFF];
    printf("%s%s%s%s%s%s%s%s%s",s, fN, uI, d, t, ac, fP, af, e);
    sprintf(entry,"%s%s%s%s%s%s%s%s%s",s, fN, uI, d, t, ac, fP, af, e);


	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(logPath, "a");

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(entry, strlen(entry), 1, original_fopen_ret);
    fclose(original_fopen_ret);
	free(fingerPrint);
	return 0;
}

int checkPermissions(uid_t userID, gid_t groupID, struct stat sb, const char *octal_mode, const char *mMode){
    /* OWNER: octal_mode[3] | GROUP: octal_mode[4] | OTHERS: octal_mode[5] */
    int flag = 0;
        /* OTHERS */
    if(mMode[0] == 'w' || mMode[1] == 'w' || mMode[0] == 'a' || mMode[1] == 'a' || mMode[1] == '+'){
        flag = (octal_mode[5] != '6' && octal_mode[5] != '7' && octal_mode[5] != '2' && octal_mode[5] != '3')?1:0;
    }else{
        flag = (octal_mode[5] < '4')?1:0;
    }

    if( groupID == sb.st_gid && flag == 1){ //check only if flag is raised before
        /* GROUP */
        if(mMode[0] == 'w' || mMode[1] == 'w' || mMode[0] == 'a' || mMode[1] == 'a' || mMode[1] == '+'){
            flag = (octal_mode[4] != '6' && octal_mode[4] != '7' && octal_mode[4] != '2' && octal_mode[4] != '3')?1:0;
        }else{
            flag = (octal_mode[4] < '4')?1:0;
        }
    }

    if( userID == sb.st_uid && flag == 1){ //check only if flag is raised before
        /* OWNER */
        if(mMode[0] == 'w' || mMode[1] == 'w' || mMode[0] == 'a' || mMode[1] == 'a' || mMode[1] == '+'){
            flag = (octal_mode[3] != '6' && octal_mode[3] != '7' && octal_mode[3] != '2' && octal_mode[3] != '3')?1:0;
        }else{
            flag = (octal_mode[3] < '4')?1:0;
        }
    }

    return flag;
}


int fileExists(char *filepath){
  struct stat   buffer;   
  return (stat(filepath, &buffer) == 0);
}

char *readFile(FILE *fileptr, size_t *size) {
  char *buffer;
  size_t filelen;

  fseek(fileptr, 0, SEEK_END);          // Jump to the end of the file
  filelen = ftell(fileptr);             // Get the current byte offset in the file
  rewind(fileptr);                      // Jump back to the beginning of the file

  buffer = (char *)malloc((filelen + 1) * sizeof(char));
  fread(buffer, filelen, 1, fileptr); // Read in the entire file

//  DO NOT fclose(fileptr); here, or we loose the FILE* and fail readlink

  if( filelen == 0){
      buffer[0] = '\0';
  }
  *size = filelen;
  return buffer;
}

void createLogFile(){
	if( !fileExists(logPath) ){
		FILE* fp = fopen(logPath, "w");
		if( fp == NULL ){
			printf("\nCould not create Log File at: \t%s\n",logPath);
			return;
		}
		printf("\nCreated Log File at: \t%s\n",logPath);
        char mode[] = "0666";
        int i;
        i = strtol(mode, 0, 8);
        if (chmod (logPath,i) < 0){
            perror("chmod ");
            exit(1);
        }
		printf("And made it accessibl by all.\n");
	}
}


char* getAbsPath(FILE *stream){
	if (stream){
		int fno = fileno(stream);
    	char proclnk[0xFFF];
    	char *filename = malloc(0xFFF);
        sprintf(proclnk, "/proc/self/fd/%d", fno);
		ssize_t r;

        r = readlink(proclnk, filename, 0xFFF);
        if (r < 0) {
            printf("/proc/self/fd/%d", fno);
            perror("read link error ");
            exit(1);
        }
        filename[r] = '\0';
        // printf("filename -> %s\n", filename);
		return filename;
    }
	return NULL;
}

char* executeMD5(char *data, size_t len, int* return_size){
    unsigned char *md = malloc(MD5_DIGEST_LENGTH);
    *return_size = MD5_DIGEST_LENGTH;
    MD5((unsigned char*)data, len, md);
    // printf("MD5 : \t %2X\n",md);
    return (char*)md;
}


char* createFileFingerprint(char *contents, size_t len, time_t T){
    struct  tm tm = *localtime(&T);
	char signature[len+16];
	sprintf(signature,"%s\n%02d%02d%04d%02d%02d%02d", 
            contents, tm.tm_mday, tm.tm_mon+1, 
            tm.tm_year+1900, tm.tm_hour, 
            tm.tm_min, tm.tm_sec);

    int size;
	return executeMD5(signature, len+16, &size);
}

/* For creating directory

	struct passwd *pw = getpwuid(getuid());
	const char *homedir = pw->pw_dir;
	char filepath[128];
	//respecting your $HOME =)
	sprintf(filepath,"/tmp/acLogger");//,homedir);
	printf("filepath = %s", filepath);

	struct stat sb;
	if (! (stat(dir, &sb) == 0 && S_ISDIR(sb.st_mode))) {
    //directory $HOME/.cache/acLogger does not exist/
    	mkdir(dir, 0755);
    }
    //directory $HOME/.cache/acLogger exists/

*/


/* For getting md5 through pipes and bash
	 //no more fun :-(
	char *command0[] = {"echo", timestamp, NULL};
	char *command1[] = {"cat", absPath, "-", NULL}; // "^user" matches lines starting with "user"
	char *command2[] = {"md5sum", NULL};
	char **commands[3] = {command0, command1, command2};
	pid_t pid[3]; // good practice: fork() result is pid_t, not int
    int fd[3][2];

	  // I recommend opening files now, so if you can't you won't create unecessary processes
    // int fd_file_out = open("/tmp/tmphashes.txt", O_WRONLY | O_CREAT | O_TRUNC, 00600);
    // if (fd_file_out < 0)
    // {
    //     perror("open(/tmp/tmphashes.txt)");
    //     return NULL;
    // }

    // int fd_file_logs = open("/tmp/tmplogs.txt", O_WRONLY | O_CREAT | O_TRUNC, 00600);
    // if (fd_file_logs < 0)
    // {
    //     perror("open(/tmp/tmplogs.txt)");
    //     close(fd_file_out); // Not necessary, but I like to do it explicitly
    //     return NULL;
    // }

    for (int i = 0; i < 3; i++) // If you decide to add more steps, this loop will be handy
    {
        if (pipe(fd[i]) < 0)
        {
            perror("pipe");
            // close(fd_file_out);
            // close(fd_file_logs);
            if (i > 0)
            {
                close(fd[i - 1][0]);
            }
            return NULL;
        }

        pid[i] = fork();
        if (pid[i] < 0)
        {
            perror("fork()");
            // close(fd_file_out);
            // close(fd_file_logs);
            if (i > 0)
            {
                close(fd[i - 1][0]);
            }
            close(fd[i][0]);
            close(fd[i][1]);
            return NULL;
        }

        if (pid[i] == 0)
        {
            close(fd[i][0]); // First thing to do: close pipes and files you don't need any more
            // close(fd_file_out);

            close(1);
            dup(fd[i][1]);
            close(fd[i][1]); // duplicated pipes are not useful any more

            close(2); // Also need to redirect stderr
            // dup(fd_file_logs);
            // close(fd_file_logs);

            if (i > 0)
            {
                close(0); // Also need to redirect stdin if this is not first process
                dup(fd[i - 1][0]);
                close(fd[i - 1][0]);
            }

            execvp(commands[i][0], commands[i]); // In a loop, we need a execv()/execvp()/execvpe() call
            return NULL; // Should not be reached;
        }

        // sub process either did execvp() or return, he won't reach this point
        close(fd[i][1]);
        if (i > 0)
        {
            close(fd[i - 1][0]);
        }
    }

    // close(fd_file_logs);

    // close(0);
    // dup(fd[2 - 1][0]);
    // close(fd[2 - 1][0]);

    // close(1);
    // dup(fd_file_out);
    // close(fd_file_out);

    // execvp(commands[2][0], commands[2]);
    // perror("execvp");
    return NULL;
	// *return_size = size;
	// return buffer;
*/


/* GIDs

    // gid_t group;
    // long ngroups_max = sysconf(_SC_NGROUPS_MAX);
    // int ngroups = getgroups(ngroups_max, &group);
    // gid_t groups[ngroups];

    // printf("\n%s\n%s\n%d\n",getlogin(),absPath,getegid());
    // if (getgrouplist(getlogin(), getegid(), groups, &ngroups) == -1) {
    //     fprintf(stderr, "getgrouplist() returned -1; ngroups = %d\n",
    //             ngroups);
    //     exit(EXIT_FAILURE);
    // }
    // // Display list of retrieved groups, along with group names
    // fprintf(stderr, "ngroups = %d\n", ngroups);
    // for (int j = 0; j < ngroups; j++) {
    //     printf("%d\t", groups[j]);
    // }

*/