#include "rsa.h"
#include "utils.h"
#include <stdlib.h>

int verbose = 0;
void setVerbose(int v){ verbose = v; }
int isVerbose(){ return verbose; }


/*		Calculate an estimation of prime
 *			numbers there are
 *				until n.
 *
 * 	x 	 		  ||π(x) 		|x/ln x 	|x/(ln x-1)
 *  1000 		  ||168 		|145 		  |169 
 *  10000     ||1229 		|1086 		|1218
 * 	100000 		||9592 		|8686 		|9512
 * 	1000000 	||78498 	|72382 		|78030
 * 	10000000 	||664579 	|620420 	|661459
 */
int sieve_estimate(int n) { 
  return floor(n / (log(n) - 1)); 
}

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
      if (b != 0)
        return gcd(b, a % b);
    else
        return a;
}

/*
 * Chooses 'e' where
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t fi_n, size_t* primes, size_t poolSize) {
  size_t e;
  // the bigger the e the better
  int start= (fi_n>1000) ? 3 : 0; //primes[3]=7
  int i;
  for (i = start; i < fi_n; i++) { 
    if ((gcd(primes[i%poolSize], fi_n) == 1) && (primes[i%poolSize] % fi_n != 0))
      break;
  }
  e = primes[i];

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
 *	x*a ≡ 1(mod b).
 */
size_t mod_inverse(size_t a, size_t b) {
  size_t x;
  a = a % b;
  for (x = 1; x < b; x++)
      if ((a * x) % b == 1)
          return x;
  return -1;
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


  p = primes[getRandom(prime_sz)];
  q = p; 
  while(q == p){
    q = primes[getRandom(prime_sz)];
  }
  n = p * q;
  fi_n = ((p - 1) * (q - 1));
  e = choose_e(fi_n, primes, prime_sz);
  

  d = mod_inverse(e, fi_n);

  size_t pubKey[2], privKey[2];
  pubKey[0] = n;
  pubKey[1] = d;
  privKey[0] = n;
  privKey[1] = e;

  if( verbose ){
    printf("The pool created:\n");
    for (i = 0; i < prime_sz; i++) {
      if ((i % 16) == 0 || i == 0) {
        printf("\n");
      }
      printf("%zu\t", primes[i]);
    }
    
    printf("\n p = %zu \tq = %zu", p, q);
    printf("\n n = %zu", n);
    printf("\n fi_n = %zu", fi_n);

    printf("\nI chose e as: %zu\n", e);
    
    printf("\nI chose d as: %zu\n", d);

    printf("PUBLIC:\n");
    printf("n: %zu \td: %zu\n", pubKey[0], pubKey[1]);
    printf("PRIVATE\n");
    printf("n: %zu \te: %zu\n", privKey[0], privKey[1]);
  }

  writeFile("./public.key", pubKey, 2, SIZE_T);
  writeFile("./private.key", privKey, 2, SIZE_T);

  //free
  free(primes);
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
  size_t key_len;
  size_t *key = readFile(key_file, &key_len, SIZE_T);
  size_t message_len;
  unsigned char *message = readFile(input_file, &message_len, UCHAR);

  size_t *ciph = malloc(sizeof(size_t) * message_len);
  size_t j;
  for (j = 0; j < message_len; j++) {
    // cipher^d mod n
    ciph[j] = compute((char)message[j], key[1], key[0]);
  }

  if( verbose ){
    printf("\nKEY: %zu and %zu", key[0], key[1]);
    printf("\nSize %zu\n", key_len);
    printf("---Message---\n");
    print_string(message, message_len);
    printf("\nmessage Size %zu\n", message_len);
    printf("---Cipher---\n");
    for (j = 0; j < message_len; j++) {
      printf("%zu\t", ciph[j]);
    }
    printf("\n Calculated from pow = %zu\tmod = %zu\n",key[1], key[0]);
  }


  writeFile(output_file, ciph, message_len, SIZE_T);

  //free
  free(key);
  free(message);
  free(ciph);
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
  size_t key_len;
  size_t *key = readFile(key_file, &key_len, SIZE_T);

  size_t ciph_len;
  size_t *ciph = readFile(input_file, &ciph_len, SIZE_T);
  int message_len = ciph_len/8;
  unsigned char *message = malloc(sizeof(char) * message_len);
  int j;
  for (j = 0; j < message_len; j++) {
    // cipher^d mod n
    message[j] = (unsigned char) ( compute(ciph[j], key[1], key[0]) % 128);
  }
  
  if( verbose ){
    printf("\nREAD KEY: %zu and %zu", key[0], key[1]);
    printf("\nAnd Size %zu\n", key_len);
    printf("\nCipher Size %zu\n", ciph_len);
    printf("---Cipher---\n");
    for (j = 0; j < message_len; j++) {
      printf("%zu\t", ciph[j]);
    }
    printf("\n");
    printf("---Message---\n");
    print_string(message, message_len);
    printf("\n Calculated from pow=%zu\tmod=%zu\n",key[1], key[0]);
  }



  writeFile(output_file, message, message_len, UCHAR);
  
  //free
  free(key);
  free(message);
  free(ciph);
}

/**
 * Computes a^b mod c
 *
 * m^p modulo n = m^(p%f(n)) modulo n
 *
 * (a^5) = a^2 * a^2 * a
 */
size_t compute(size_t a, size_t b, size_t c) {
  size_t res = 1;
  // int i;
  // for(i = 63; i >= 0; i++){
  //   res = (long long)( pow(res,2) * pow(a,(b >> i) & 1) ) % c ;
  // }
  // res = fmod(pow(a,b),c);
  //---------------------------------------------
  a = a % c;
  while(b > 0) {
  	if(b & 1) {
  		res = (res * a) % c;
  	}
  	a = (a * a) % c;
  	b = floor(b/2);
  }
  return res;
}

/* *************DEV NOTES******************

c:=1
for i:=ℓ down to 0 do
c:= c^2 ⋅ m^e_i % n
return c

ℓ e bits.

take the k'th bit (e >> k) & 1

*/

/*
function MultiPrecisionREDC is
    Input: Integer N with gcd(B, N) = 1, stored as an array of p words,
           Integer R = Br,     --thus, r = logB R
           Integer N′ in [0, B − 1] such that NN′ ≡ −1 (mod B),
           Integer T in the range 0 ≤ T < RN, stored as an array of r + p words.

    Output: Integer S in [0, N − 1] such that TR−1 ≡ S (mod N), stored as an
array of p words.

    Set T[r + p] = 0  (extra carry word)
    for 0 ≤ i < r do
        --loop1- Make T divisible by Bi+1

        c ← 0
        m ← T[i] ⋅ N′ mod B
        for 0 ≤ j < p do
            --loop2- Add the low word of m ⋅ N[j] and the carry from earlier,
and find the new carry

            x ← T[i + j] + m ⋅ N[j] + c
            T[i + j] ← x mod B
            c ← ⌊x / B⌋
        end for
        for p ≤ j ≤ r + p − i do
            --loop3- Continue carrying

            x ← T[i + j] + c
            T[i + j] ← x mod B
            c ← ⌊x / B⌋
        end for
    end for

    for 0 ≤ i ≤ p do
        S[i] ← T[i + r]
    end for

    if S ≥ N then
        return S − N
    else
        return S
    end if
end function


 */