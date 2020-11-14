#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <sys/types.h>
#include <fcntl.h>
#include <pwd.h>
#include "util.h"

char *logPath = "/tmp/acLogger";

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
	}
}

char* getAbsPath(FILE *stream){
	if (stream){
		int fno = fileno(stream);
    	int MAXSIZE = 0xFFF;
    	char proclnk[0xFFF];
    	char *filename = malloc(0xFFF);
        sprintf(proclnk, "/proc/self/fd/%d", fno);
		ssize_t r;

        r = readlink(proclnk, filename, MAXSIZE);
        if (r < 0)
        {
            perror("read link error: ");
            exit(1);
        }
        filename[r] = '\0';
        // printf("filename -> %s\n", filename);
		return filename;
    }
	return NULL;
}

char* runBash(char *bash_cmd, int return_size){
	char *buffer = malloc(return_size+1);
	FILE *pipe;

	printf("BASHCMD: %s\n",bash_cmd);
	pipe = popen(bash_cmd, "r");

	if (NULL == pipe) {
	    perror("pipe");
	    exit(1);
	}

	fread(buffer, return_size, sizeof(char), pipe);

	buffer[return_size] = '\0'; 

	pclose(pipe);

  	printf("Subprocess finished. RES: %s\n",buffer);
	return buffer;
}

char* executeMD5(char *data, size_t len, int* return_size){
    unsigned char *md = malloc(MD5_DIGEST_LENGTH);
    *return_size = MD5_DIGEST_LENGTH;
    MD5((unsigned char*)data, len, md);
    printf("MD5 : \t %2X\n",md);
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

FILE *
fopen(const char *path, const char *mode) 
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
	/* ... */
	uid_t userID =  getuid();
	time_t T= time(NULL);

	createLogFile();
    size_t  cont_len  = 0;
    char*   file_cont = readFile(original_fopen_ret, &cont_len);

	appendEntryToLogfile(file_cont, cont_len, getAbsPath(original_fopen_ret), userID, T, access, flag);
	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	int access = 2, flag = 0;
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	/* add your code here */
	/* ... */
	uid_t userID =  getuid();
	time_t T= time(NULL);

    struct stat sb;
    size_t  cont_len  = 0;
    char*   file_cont = "";

    if (stat(getAbsPath(stream), &sb) == -1) {
        perror("stat");
        exit(EXIT_FAILURE);
    }

    printf("Mode:                     %lo (octal)\n",
            (unsigned long) sb.st_mode);
    printf("Link count:               %ld\n", (long) sb.st_nlink);
    printf("Ownership:                UID=%ld   GID=%ld\n",
            (long) sb.st_uid, (long) sb.st_gid);
    printf("Last status change:       %s", ctime(&sb.st_ctime));
    printf("Last file access:         %s", ctime(&sb.st_atime));
    printf("Last file modification:   %s", ctime(&sb.st_mtime));

    if(userID != sb.st_uid && userID != sb.st_gid && userID != 0){
        flag = 1;
    }else{
        file_cont = readFile(stream, &cont_len);
    }

	createLogFile();
	appendEntryToLogfile(file_cont, cont_len, getAbsPath(stream), userID, T, access, flag);

    if(!flag){
	    /* call the original fwrite function */
	    original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	    original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
        free(file_cont);
        
    }
	return original_fwrite_ret;
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