#include "simple_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

const char *randomDevice = "/dev/urandom";

void getNcharsFromURandom(int n, byte **buf) {

  int randFD = checkSysCall(open(randomDevice, 'r'), "Error opening device.");

  byte res[n];

  int i = 0;
  byte c;
  while (i < n) {
    checkSysCall(read(randFD, &c, sizeof(char)), "Error reading from device");
    res[i++] = c;
  }
  strcpy((char*)*buf, (const char*)res);
}

int readInput(byte array[]) {
  byte c;
  int count = 0;

  while ((c = getchar()) != '\n' && count < INITIAL_SIZE - 2) {
    if ((c < 48) || (57 < c && c < 65) || (90 < c && c < 97) || (122 < c)) {
      continue;
    }
    array[count] = c;
    count++;
  }
  if (count >= INITIAL_SIZE - 2 && c != "\n") {
    /*kathe fora pou ftanw na exw ena teleutaio
     *eleuthero keli (-2 gt arxizw apo 0) kanw
     *alocation ton diplasio xwro kai deixnw ekei*/
    int realocs = 0;
    unsigned long reallocCount = 0;
  jumper:
    ++realocs;

    reallocCount = (unsigned long)(INITIAL_SIZE * 2 * realocs);
    array[count] = (byte *)malloc(reallocCount);
    if (array == NULL) {
      printf("out of memory! D:\n");
      return -1;
    }
    // printf("reallocs: %d and the counter: %d\n", realocs, count);
    while ((c = getchar()) != '\n') {
      if ((c < 48) || (57 < c && c < 65) || (90 < c && c < 97) || (122 < c)) {
        continue;
      }
      array[count] = c;
      count++;
      if (count >= reallocCount - 2)
        goto jumper;
    }
  }
  return count;
}

void otpEncrypt(byte *input, byte *key, byte *output) {
  // check sizes
  int outSize = strlen((const char*)input);
  if (strlen((const char*)key) < outSize) {
    return;
  }
  // encrypt
  int i;
  for (i = 0; i < outSize; i++) {
    output[i] = input[i] ^ key[i];
  }
}

int readNumber(byte array[]) {
  byte c;
  int count = 0;

  while ((c = getchar()) != '\n' && count < INITIAL_SIZE - 1) {
    if ((c < 48) || (57 < c && c < 65) || (90 < c && c < 97) || (122 < c)) {
      continue;
    }
    array[count] = c;
    count++;
  }
  return atoi((const char*)array)%256;
}

void caesarsCipher(struct CaesarsChipher c, bool encrypt) {
  int shifts = c.secKey %123;
  printf("c.len : %d\n",c.len);
  printf("shifts : %d\n",shifts);
  int i;
  byte temp[c.len];

  if (encrypt) {
    for (i = 0; i < c.len; i++) {
      temp[i] = (byte) ( (int)(c.input[i] + shifts) % 123);
      // printf("temp : %d\n", (int)temp[i]);
      if (temp[i] >= 0 && temp[i] < 10) { // goes to 0-9
        temp[i] = temp[i] + 48;
      } else if (temp[i] > 9 && temp[i] < 37) { // goes to A-Z
        temp[i] = temp[i] + 54;
      } else if (temp[i] > 36 && temp[i] < 48) { // goes to a-k
        temp[i] = temp[i] + 60;
      } else if (temp[i] > 57 && temp[i] < 65) {
        temp[i] = temp[i] + 7; // in between 9 and A
      } else if (temp[i] > 90 && temp[i] < 97) {
        temp[i] = temp[i] + 6; // in between Z and a
      } else {
        temp[i] = temp[i];
      }
      // printf("temp after : %d\n", (int)temp[i]);
    }
    printf("encrypt temp : %s\n", temp);
    memcpy((char*)c.output, (const char*)temp, c.len);
  } else {

    for (i = 0; i < strlen((const char*)c.output); i++) {
      temp[i] = (byte) ( (int)(c.output[i] - shifts) ) % 123;
      printf("temp : %d\n", (int)temp[i]);

      if (temp[i] >= 0 && temp[i] < 10) { 
        temp[i] = (temp[i] - 171);//goes to 0-9

      } else if (temp[i] > 9 && temp[i] < 37) { // goes to A-Z
        temp[i] = (temp[i] - 177);

      } else if (temp[i] > 36 && temp[i] < 48) { // goes to a-k
        temp[i] = (temp[i] - 181);

      } else if (temp[i] > 57 && temp[i] < 65) {
        temp[i] = temp[i] - 7; // in between 9 and A

      } else if (temp[i] > 90 && temp[i] < 97) {
        temp[i] = temp[i] - 6; // in between Z and a

      } else {
        temp[i] = temp[i];
      }
      // if (temp[i] >= 0 && temp[i] < 10) { 
      //   temp[i] = temp[i] + 97;
      // } else if (temp[i] > 25 && temp[i] < 48) { 
      //   temp[i] = temp[i] + 39;
      // } else if (temp[i] > 57 && temp[i] < 65) {
      //   temp[i] = temp[i] - 7; // in between 9 and A
      // } else if (temp[i] > 90 && temp[i] < 97) {
      //   temp[i] = temp[i] - 6; // in between Z and a
      // } else {
      //   temp[i] = temp[i];
      // }
      printf("temp after : %d\n", (int)temp[i]);
    }
    byte *tmp2 = temp;
    printf("[Caesars] decrypted:  : %s\n", tmp2);
  }
}

int checkSysCall(int n, char* err){    //syscall management
    if (n != -1)
        return n;
    perror(err);
    exit(1);
};
