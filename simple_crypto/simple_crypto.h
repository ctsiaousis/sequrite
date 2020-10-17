#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

#include  <stdio.h>         /* atoi */
#include  <stdbool.h>       /* bool */
#include  <unistd.h>        /* fork sleep */
#include  <stdlib.h>        /* exit  */
#include  <string.h>        /* strcpy */
#include  <ctype.h>         /* isprint */



/************************* GENERAL *************************/
#define INITIAL_SIZE 64
#define ULL_DIGITS 20

typedef unsigned char byte;

int checkSysCall(int n, char* err);

int readInput(byte array[]);

/*********************** One-Time Pad ***********************/
struct OneTimePad {
    int len;
    byte *input;
    byte *secKey;
    byte *output;
};

void getNcharsFromURandom(int n, byte **m);

void otpEncrypt(byte *input, byte *key, byte *output);

/********************** CaesarsChipher **********************/
struct CaesarsChipher {
    int len;
    int secKey;
    byte *input;
    byte *output;
};

int readNumber(byte array[]);

void caesarsCipher(struct CaesarsChipher c, bool encrypt);

/********************* VigenèresChipher *********************/

#endif