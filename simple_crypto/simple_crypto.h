#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

#include  <stdio.h>
#include  <sys/types.h>
#include  <unistd.h>        /* fork sleep */
#include  <stdlib.h>        /* exit  */
#include  <string.h>        /* strcpy */
#include  <ctype.h>         /* isprint */


#define INITIAL_SIZE 16

typedef unsigned char byte;

struct OneTimePad {
    int len;
    unsigned char *input;
    unsigned char *secKey;
    unsigned char *output;
};

int checkSysCall(int n, char* err){    //syscall management
    if (n != -1)
        return n;
    perror(err);
    exit(1);
};

void getNcharsFromURandom(int n, char **);

int readInput(unsigned char array[]);

#endif