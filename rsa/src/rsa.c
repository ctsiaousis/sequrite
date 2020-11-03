#include "rsa.h"
#include "utils.h"
#include <stdlib.h>

/*		Calculate an estimation of prime
 *			numbers there are
 *				until n.
 *
 * 	x 	 		  ||π(x) 		|x/ln x 	|x/(ln x -1)
 * 	1000 		  ||168 		|145 		|169
 * 	10000 		||1229 		|1086 		|1218
 * 	100000 		||9592 		|8686 		|9512
 * 	1000000 	||78498 	|72382 		|78030
 * 	10000000 	||664579 	|620420 	|661459
 */
int sieve_estimate(int n) { return floor(n / (log(n) - 1)); }

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *sieve_of_eratosthenes(int limit, int *primes_sz) {
  size_t *primes;

  /*

let A be an array of Boolean values, indexed by integers 2 to n,
initially all set to true.

for i = 2, 3, 4, ..., not exceeding √n do
  if A[i] is true
      for j = i2, i2+i, i2+2i, i2+3i, ..., not exceeding n do
          A[j] := false

return all i such that A[i] is true.
  */
  int *A = malloc(sizeof(int) * (limit));
  int i;
  for (i = 0; i < limit; i++) {
    A[i] = 1;
  }
  int k;
  for (i = 2; i < (int)floor(sqrt(limit)); i++) {
    if (A[i] == 1) {
      for (k = i * i; k < limit; k += i) {
        A[k] = 0;
      }
    }
  }

  size_t estimate = sieve_estimate(limit);
  primes = malloc(sizeof(size_t) * estimate);
  k = 0;
  for (i = 2; i < limit; i++) {
    if (A[i] == 1) {
      primes[k] = (size_t)i;
      k++;
    }
  }

  printf("k: %d\n", (k));

  *primes_sz = k;
  free(A);
  return primes;
}

/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int gcd(int a, int b) {
  if (a == 0)
    return b;
  return gcd(b % a, a);
}

/*
 * Chooses 'e' where
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t fi_n) {
  size_t e;

  int i;
  for (i = fi_n / 8; i < fi_n; i++) { // the bigger the e the better
    if ((gcd(i, fi_n) == 1) && (i % fi_n != 0))
      break;
  }
  e = i;

  return e; // this is also prime!
}

/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 *
 *	ed ≡ 1(mod φ(n)).
 */
size_t mod_inverse(size_t a, size_t b) {
  size_t d;
  int m0 = b;
  int y = 0;
  int x = 1;

  if (b == 1)
    return 0;

  while (a > 1) {
    // q is quotient
    int q = a / b;
    int t = b;
    b = a % b;
    a = t;
    t = y;

    // Update y and x
    y = x - q * y;
    x = t;
  }

  // Make x positive
  if (x < 0)
    x += m0;

  d = x;
  return d;
}

/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(void) {
  size_t p;
  size_t q;
  size_t n;
  size_t fi_n;
  size_t e;
  size_t d;

  /* TODO */
  int i;
  int prime_sz;
  size_t *primes = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, &prime_sz);
  for (i = 0; i < prime_sz; i++) {
    if ((i % 16) == 0 || i == 0) {
      printf("\n");
    }
    printf("%zu\t", primes[i]);
  }

  p = primes[getRandom(prime_sz)];
  q = primes[getRandom(prime_sz)];
  printf("\n p=%zu \tq=%zu", p, q);
  n = p * q;
  printf("\n n=%zu", n);
  fi_n = ((p - 1) * (q - 1));
  printf("\n fi_n=%zu", fi_n);
  e = choose_e(fi_n);
  printf("\nI chose e as: %zu \t to be sure, gcd(e,fi_n)=%d\n", e,
         gcd(e, fi_n));

  d = mod_inverse(e, fi_n);
  printf("\nI chose d as: %zu\n", d);

  size_t pubKey[2], privKey[2];
  pubKey[0] = n;
  pubKey[1] = d;
  privKey[0] = n;
  privKey[1] = e;

  printf("PUBLIC:\n");
  printf("%zu \t%zu\n", pubKey[0], pubKey[1]);
  printf("PRIVATE\n");
  printf("%zu \t%zu\n", privKey[0], privKey[1]);
  writeFile("./test.pubKey", pubKey, 2);
  //TEEEEEST
  char *message = "this is a stupid test.";
  size_t *cipher = malloc(sizeof(size_t) * 22);

  size_t j;
  for (j = 0; j < 22; j++) {
    // mesage^e mod n
    cipher[j] = modpow(message[j], e, n);
  }

  for (j = 0; j < 22; j++) {
    printf("%zu\t",cipher[j]);
  }
  char* new_message = malloc(sizeof(char) * 22);
  for (j = 0; j < 22; j++) {
    // cipher^d mod n
    new_message[j] = (char)modpow(cipher[j], d, n);
  }

  printf("\n");
  for (j = 0; j < 22; j++) {
    printf("%c\t",message[j]);
  }
}

/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_encrypt(char *input_file, char *output_file, char *key_file) {
  // read files
  // size_t message_len;
  // size_t *message = readFile(input_file,&message_len);
  size_t key_len;
  size_t *key = readFile(key_file, &key_len);
  printf("\nREAD KEY: %zu and %zu", key[0], key[1]);
  printf("\nAnd Size %zu\n", key_len);

  char *message = "this is a stupid test.";
  size_t *cipher = malloc(sizeof(size_t) * 22);

  size_t n = key[0];
  size_t e = key[1];
  size_t i;
  for (i = 0; i < 22; i++) {
    // mesage^e mod n
    cipher[i] = modpow(message[i], e, n);
  }

  // for (i = 0; i < 22; i++) {
  //   printf("%zu\t",cipher[i]);
  // }

  // printf("\n");
}

/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_decrypt(char *input_file, char *output_file, char *key_file) {

  /* TODO */
  // char *message = "this is a stupid test.";
  // size_t *cipher = malloc(sizeof(size_t) * 22);
  // for (j = 0; j < 2; i++) {
  //   // cipher^d mod n
  //   message[j] = (char)modpow(cipher[j], d, n);
  // }

  // for (j = 0; j < 2; j++) {
  //   printf("%c\t",message[j]);
  // }
}
