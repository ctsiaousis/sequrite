#include "simple_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int checkSysCall(int n, char *err) { // syscall management
  if (n != -1)
    return n;
  perror(err);
  exit(1);
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
  if (count >= INITIAL_SIZE - 2 && c != '\n') {
    /*kathe fora pou ftanw na exw ena teleutaio
     *eleuthero keli (-2 gt arxizw apo 0) kanw
     *alocation ton diplasio xwro kai deixnw ekei*/
    int realocs = 0;
    unsigned long reallocCount = 0;
  jumper:
    ++realocs;

    reallocCount = (unsigned long)(INITIAL_SIZE * 2 * realocs);
    array[count] = (byte)malloc(reallocCount);
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
      if (count >= (int)reallocCount - 2)
        goto jumper;
    }
  }
  return count;
}

void getNcharsFromURandom(int n, byte **buf) {
  const char *randomDevice = "/dev/urandom";
  int randFD = checkSysCall(open(randomDevice, O_RDONLY), "Error opening device.");

  byte res[n];

  int i = 0;
  byte c;
  while (i < n) {
    checkSysCall(read(randFD, &c, sizeof(char)), "Error reading from device");
    res[i++] = c;
  }
  strcpy((char *)*buf, (const char *)res);

  close(randFD);
}

void otpEncrypt(byte *input, byte *key, byte *output) {
  // check sizes
  int outSize = strlen((const char *)input);
  if ((int)strlen((const char *)key) < outSize) {
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
  return atoi((const char *)array) % 256;
}

void caesarsCipher(struct CaesarsChipher c, bool encrypt) {

  int shifts = c.secKey % 63; // my subset is 62 characters
  int i;

  if (encrypt) {//take c.input translate to c.cipher,
          // then shift and then retranslate to c.output

    //create a cipher array with 0<=value<=62
    for (i = 0; i < c.len; i++) {
      if (c.input[i] >= '0' && c.input[i] <= '9') {
        c.cipher[i] = c.input[i] - 48;
      } else if (c.input[i] >= 'A' && c.input[i] <= 'Z') {
        c.cipher[i] = c.input[i] - 54;
      } else if (c.input[i] >= 'a' && c.input[i] <= 'z') {
        c.cipher[i] = c.input[i] - 60;
      } else {
        // no wrong input handling
        // trusting user lol
      }
    }
    //shift on that cipher and then retranslate to ASCII
    for (i = 0; i < c.len; i++) {
      c.cipher[i] = (byte)((int)(c.cipher[i] + shifts));
      // c.cipher[i] = (c.cipher[i] < 0) ? c.cipher[i] + 62 : c.cipher[i];
      c.cipher[i] = (c.cipher[i] > 62) ? c.cipher[i] - 63 : c.cipher[i];

      if (c.cipher[i] <= 10) { // 0=9
        c.output[i] = c.cipher[i] + 48;
      } else if (c.cipher[i] >= 11 && c.cipher[i] <= 36) { // A-Z
        c.output[i] = c.cipher[i] + 54;
      } else if (c.cipher[i] >= 37 && c.cipher[i] <= 62) { // a-z
        c.output[i] = c.cipher[i] + 60;
      } else {
        // no wrong input handling
        // trusting user lol
      }
    }
  } else { //take c.output translate to c.cipher,
          // then shift and then retranslate to c.input
    for (i = 0; i < c.len; i++) {
      if (c.output[i] >= '0' && c.output[i] <= '9') {
        c.cipher[i] = c.output[i] - 48;
      } else if (c.output[i] >= 'A' && c.output[i] <= 'Z') {
        c.cipher[i] = c.output[i] - 54;
      } else if (c.output[i] >= 'a' && c.output[i] <= 'z') {
        c.cipher[i] = c.output[i] - 60;
      } else {
        // no wrong input handling
        // trusting user lol
      }
    }
    //shift on that cipher and then retranslate to ASCII
    for (i = 0; i < c.len; i++) {
      c.cipher[i] = (byte)((int)(c.cipher[i] - shifts));
      // c.cipher[i] = (c.cipher[i] < 0) ? c.cipher[i] + 62 : c.cipher[i];
      c.cipher[i] = (c.cipher[i] > 62) ? c.cipher[i] - 63 : c.cipher[i];

      if (c.cipher[i] <= 10) { // 0=9
        c.input[i] = c.cipher[i] + 48;
      } else if (c.cipher[i] >= 11 && c.cipher[i] <= 36) { // A-Z
        c.input[i] = c.cipher[i] + 54;
      } else if (c.cipher[i] >= 37 && c.cipher[i] <= 62) { // a-z
        c.input[i] = c.cipher[i] + 60;
      } else {
        // no wrong input handling
        // trusting user lol
      }
    }
  }
}

int readCaps(byte array[]){
  byte c;
  int count = 0;

  while ((c = getchar()) != '\n' && count < INITIAL_SIZE - 2) {
    if ((c < 'A') || ('Z' < c)) {
      continue;
    }
    array[count] = c;
    count++;
  }
  if (count >= INITIAL_SIZE - 2 && c != '\n') {
    /*kathe fora pou ftanw na exw ena teleutaio
     *eleuthero keli (-2 gt arxizw apo 0) kanw
     *alocation ton diplasio xwro kai deixnw ekei*/
    int realocs = 0;
    unsigned long reallocCount = 0;
  jumper:
    ++realocs;

    reallocCount = (unsigned long)(INITIAL_SIZE * 2 * realocs);
    array[count] = (byte)malloc(reallocCount);
    if (array == NULL) {
      printf("out of memory! D:\n");
      return -1;
    }
    // printf("reallocs: %d and the counter: %d\n", realocs, count);
    while ((c = getchar()) != '\n') {
      if ((c < 'A') || ('Z' < c)) {
        continue;
      }
      array[count] = c;
      count++;
      if (count >= (int)reallocCount - 2)
        goto jumper;
    }
  }
  return count;
}


void vigeneres(struct VigeneresChipher v, bool encrypt){
  int i;
  int keyCycle = (int)strlen((const char*)v.secKey);
  if(encrypt){
    for(i = 0; i < v.len; i++){
      v.output[i]=65+(v.input[i] + v.secKey[i%(keyCycle)])%26;
    }
  }else {
    for(i = 0; i < v.len; i++){
      v.input[i]=65+(v.output[i] - v.secKey[i%(keyCycle)]+26)%26;
    }
    if(v.len == 0 ) //prevent zero inputs
      v.input[0] = '\0';
  }
}

void printMemberCaesars(struct CaesarsChipher c, int which){
  int i;
  if(which == 0){ //print input
    for(i = 0; i < c.len; i ++){
      putchar(c.input[i]);
    }
  }else { //print output
    for(i = 0; i < c.len; i ++){
      putchar(c.output[i]);
    }
  } 
  //print new line
  printf("\n");

}

void printMemberVigeneres(struct VigeneresChipher c, int which){
  int i;
  if(which == 0){ //print input
    for(i = 0; i < c.len; i ++){
      putchar(c.input[i]);
    }
  }else { //print output
    for(i = 0; i < c.len; i ++){
      putchar(c.output[i]);
    }
  } 
  //print new line
  printf("\n");

}