#include "simple_crypto.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

const char *randomDevice = "/dev/urandom";

void getNcharsFromURandom(int n, char **buf) {

  int randFD = checkSysCall(open(randomDevice, 'r'), "Error opening device.");

  byte res[n];

  int i = 0;
  byte c;
  while (i < n) {
    checkSysCall(read(randFD, &c, sizeof(char)), "Error reading from device");
    res[i++] = c;
  }
  strcpy(*buf, res);
}

int readInput(byte array[]) {
  byte c;
  int count = 0;

  while ((c = getchar()) != '\n' && c != EOF && count < INITIAL_SIZE-2) {
    if (c < 32 || c > 127) { // ignore non printables
      continue;
    }
    array[count] = c;
    count++;
  }
  if (count >= INITIAL_SIZE-2 && c != "\0") {
    /*kathe fora pou ftanw na exw ena teleutaio
     *eleuthero keli (-2 gt arxizw apo 0) kanw
     *alocation ton diplasio xwro kai deixnw ekei*/
    int realocs = 0;
    unsigned long reallocCount = 0;
  jumper:
    ++realocs;
    
    reallocCount = (unsigned long) (INITIAL_SIZE * 2 * realocs);
    array[count] = (byte*)malloc(reallocCount);
    if(array == NULL){
        printf("out of memory! D:\n");
        return -1;
    }
    // printf("reallocs: %d and the counter: %d\n", realocs, count);
    while ((c = getchar()) != '\n' && c != EOF) {
    // printf("counterounter: %d\n", count);
      array[count] = c;
      count++;
      if (count >= reallocCount-2)
        goto jumper;
    }
  }
  return count;
}

int main() {
  struct OneTimePad first;
  byte *in1 = (byte*)malloc(INITIAL_SIZE*sizeof(byte));
  printf("[OTP] input: ");

  first.len = readInput(in1);
  printf("%s\n", in1);

  first.output = malloc(sizeof(byte) * first.len);
  first.secKey = malloc(sizeof(byte) * first.len);
  first.input = malloc(sizeof(byte) * first.len);

  strcpy(first.input, in1);
  // memcpy(first.input, in1, first.len);

  printf("My input: %s  with size %lu\n", first.input, strlen(first.input));

  getNcharsFromURandom(first.len, &first.secKey);

  printf("[OTP] encrypted: %x\n", first.secKey);
  printf("Of size: %ld\n", strlen(first.secKey));
  return 0;
}

// if (c < 32 || c > 127) { //(c < 48) || (57 < c && c < 65) || (90 < c && c <
//                          // 97) || (122 < c)){
//                          // isprint(c) == 0){
//   // i--;
//   continue;
// }