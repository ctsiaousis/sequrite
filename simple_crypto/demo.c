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
  free(in1);

  // printf("My input: %s  with size %lu\n", first.input, strlen(first.input));

  getNcharsFromURandom(first.len * 2, &first.secKey);

  // printf("[OTP] sec Key in hex: %x\n", (unsigned int)first.secKey);
  otpEncrypt(first.input, first.secKey, first.output);

  printf("[OTP] encrypted: %#x\n", (unsigned int)first.output);
  otpEncrypt(first.output, first.secKey, first.input);
  printf("[OTP] decrypted: %s\n", first.input);

  /********************** CaesarsChipher **********************/
  struct CaesarsChipher second;
  byte *in2 = (byte *)malloc(INITIAL_SIZE * sizeof(byte));
  byte csKey[ULL_DIGITS];

  printf("[Caesars] input: ");
  second.len = (int)readInput(in2);

  second.input = malloc(sizeof(byte) * (second.len));
  second.cipher = malloc(sizeof(byte) * (second.len));
  second.output = malloc(sizeof(byte) * (second.len));

  strcpy((char*)second.input, (const char*)in2);
//   memcpy((char*)second.output, (const char*)in2, second.len);
  free(in2);

  printf("[Caesars] key: ");
  second.secKey = readNumber(csKey);
  // printf("My key: %d \n", second.secKey);

  caesarsCipher(second, true);
  printf("[Caesars] encrypted: ");
  printMemberCaesars(second, 1); //1 prints c.output

  caesarsCipher(second, false);
  printf("[Caesars] decrypted: ");
  printMemberCaesars(second, 0); //0 prints c.input

/********************* VigenèresChipher *********************/
  struct VigeneresChipher third;
  byte *in3 = (byte *)malloc(INITIAL_SIZE * sizeof(byte));
  byte *key3 = (byte *)malloc(INITIAL_SIZE * sizeof(byte));

  printf("[Vigenere] input: ");
  third.len = (int)readCaps(in3);

  third.output = malloc(sizeof(byte) * third.len);
  third.secKey = malloc(sizeof(byte) * third.len);
  third.input  = malloc(sizeof(byte) * third.len);

  strcpy((char*)third.input, (const char*)in3);
  free(in3);

  printf("[Vigenere] key: ");
  readCaps(key3);
  //if key is bigger i dont care.
  memcpy((char*)third.secKey, (const char*)key3, third.len);
  free(key3);

  vigeneres(third, true);
  printf("[Vigenere] encrypted: ");
  printMemberVigeneres(third,1); //1 prints c.output

  vigeneres(third, false);
  printf("[Vigenere] decrypted: ");
  printMemberVigeneres(third,0); //0 prints c.input

  return 0;
}