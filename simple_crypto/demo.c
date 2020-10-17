#include "simple_crypto.h"

int main() {
  /*********************** One-Time Pad ***********************/
  struct OneTimePad first;
  byte *in1 = (byte *)malloc(INITIAL_SIZE * sizeof(byte));
  printf("[OTP] input: ");

  first.len = readInput(in1);

  first.output = malloc(sizeof(byte) * first.len);
  first.secKey = malloc(sizeof(byte) * (first.len * 2));
  first.input = malloc(sizeof(byte) * first.len);

  strcpy((char*)first.input, (const char*)in1);
  // memcpy(first.input, in1, first.len);
  free(in1);

  // printf("My input: %s  with size %lu\n", first.input, strlen(first.input));

  getNcharsFromURandom(first.len * 2, &first.secKey);

  // printf("[OTP] sec Key in hex: %x\n", (unsigned int)first.secKey);
  otpEncrypt(first.input, first.secKey, first.output);

  printf("[OTP] encrypted: %x\n", (unsigned int)first.output);
  otpEncrypt(first.output, first.secKey, first.input);
  printf("[OTP] decrypted: %s\n", first.input);

  /********************** CaesarsChipher **********************/
  struct CaesarsChipher second;
  byte *in2 = (byte *)malloc(INITIAL_SIZE * sizeof(byte));
  byte csKey[ULL_DIGITS];

  printf("[Caesars] input: ");
  second.len = (int)readInput(in2);
  printf("real: %ld mine %d \n", strlen((const char*)in2), second.len);

  second.output = malloc(sizeof(byte) * (second.len));
  second.input = malloc(sizeof(byte) * (second.len));

  strcpy((char*)second.input, (const char*)in2);
//   memcpy((char*)second.output, (const char*)in2, second.len);
  free(in2);

  printf("[Caesars] key: ");
  second.secKey = readNumber(csKey);
  // printf("My key: %d \n", second.secKey);

  caesarsCipher(second, true);
  printf("[Caesars] encrypted: %s\n", second.output);
  caesarsCipher(second, false);
  return 0;
}