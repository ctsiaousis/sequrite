#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#define BLOCK_SIZE 16

/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t);
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *,
             unsigned char *, int);
int decrypt(unsigned char *, int, unsigned char *, unsigned char *,
            unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);

/* TODO Declare your function prototypes here... */

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len) {
  size_t i;

  if (!data)
    printf("NULL data\n");
  else {
    for (i = 0; i < len; i++) {
      if (!(i % 16) && (i != 0))
        printf("\n");
      printf("%02X ", data[i]);
    }
    printf("\n");
  }
}

/*
 * Prints the input as string
 */
void print_string(unsigned char *data, size_t len) {
  size_t i;

  if (!data)
    printf("NULL data\n");
  else {
    for (i = 0; i < len; i++)
      printf("%c", data[i]);
    printf("\n");
  }
}

/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void usage(void) {
  printf("\n"
         "Usage:\n"
         "    assign_1 -i in_file -o out_file -p passwd -b bits"
         " [-d | -e | -s | -v]\n"
         "    assign_1 -h\n");
  printf("\n"
         "Options:\n"
         " -i    path    Path to input file\n"
         " -o    path    Path to output file\n"
         " -p    psswd   Password for key generation\n"
         " -b    bits    Bit mode (128 or 256 only)\n"
         " -d            Decrypt input and store results to output\n"
         " -e            Encrypt input and store results to output\n"
         " -s            Encrypt+sign input and store results to output\n"
         " -v            Decrypt+verify input and store results to output\n"
         " -h            This help message\n");
  exit(EXIT_FAILURE);
}

/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void check_args(char *input_file, char *output_file, unsigned char *password,
                int bit_mode, int op_mode) {
  if (!input_file) {
    printf("Error: No input file!\n");
    usage();
  }

  if (!output_file) {
    printf("Error: No output file!\n");
    usage();
  }

  if (!password) {
    printf("Error: No user key!\n");
    usage();
  }

  if ((bit_mode != 128) && (bit_mode != 256)) {
    printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
    usage();
  }

  if (op_mode == -1) {
    printf("Error: No mode\n");
    usage();
  }
}

/*
 * Generates a key using a password
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
            int bit_mode) {

  /* TODO Task A */
  int i, offset, nrounds = 1;

	const unsigned char *salt = NULL;

  if (bit_mode == 128) {
	  offset = 16;
  }else{
	  offset = 32;
  }

  /*
   * Gen key & IV for AES 256 ECB mode. A SHA1 digest is used to hash the
   * supplied key material. nrounds is the number of times the we hash the
   * material. More rounds are more secure but slower.
   *
   * NOTE: EVP_BytesToKey returns the size of key in BYTES!!!
   * 
   * ECB mode should not produce an IVector. That is the case with our calls
   * EVP_aes_256/128_ecb(). If we were to use CBC we would also produce an IV.
   * Take a look on the README reference links. =)
   */
  i = EVP_BytesToKey( (offset==32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb(),
  					EVP_sha1(), salt, password, strlen((const char *)password), nrounds, key, iv);

  if (i != offset) {
    printf("Key size is %d bits - should be %d bits\n", i, offset*8);
    return;
  }

printf("the size of key is %d\n", i);
}

/*
 * Encrypts the data
 */
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
             unsigned char *iv, unsigned char *ciphertext, int bit_mode) {

  /* TODO Task B */
}

/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, int bit_mode) {
  int plaintext_len;

  plaintext_len = 0;

  /*TODO Task C */

  return plaintext_len;
}

/*
 * Generates a CMAC
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key,
              unsigned char *cmac, int bit_mode) {

  /* TODO Task D */
}

/*
 * Verifies a CMAC
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2) {
  int verify;

  verify = 0;

  /* TODO Task E */

  return verify;
}

/* TODO Develop your functions here... */

/*
 * Dump any error messages from the OpenSSL
 * error stack to the screen, and then
 * abort the program.
 */
void handleErrors(void) {
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

int encrypt_tst(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, unsigned char *ciphertext) {
  
  EVP_CIPHER_CTX *ctx;

  int mode = strlen(key);
  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(ctx, (mode == 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb(),
  								 NULL, key, iv))
    handleErrors();

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int decrypt_tst(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *key, unsigned char *iv,
                unsigned char *plaintext) {
  EVP_CIPHER_CTX *ctx;

  int mode = strlen(key);

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_DecryptInit_ex(ctx, (mode == 32)?EVP_aes_256_ecb():EVP_aes_128_ecb(),
  								NULL, key, (mode == 32)?iv:NULL))
    handleErrors();

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  /*
   * Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int main(int argc, char **argv) {
  int opt;                 /* used for command line arguments */
  int bit_mode;            /* defines the key-size 128 or 256 */
  int op_mode;             /* operation mode */
  char *input_file;        /* path to the input file */
  char *output_file;       /* path to the output file */
  unsigned char *password; /* the user defined password */

  /* Init arguments */
  input_file = NULL;
  output_file = NULL;
  password = NULL;
  bit_mode = -1;
  op_mode = -1;

  /*
   * Get arguments
   */
  while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
    switch (opt) {
    case 'b':
      bit_mode = atoi(optarg);
      break;
    case 'i':
      input_file = strdup(optarg);
      break;
    case 'o':
      output_file = strdup(optarg);
      break;
    case 'p':
      password = (unsigned char *)strdup(optarg);
      break;
    case 'd':
      /* if op_mode == 1 the tool decrypts */
      op_mode = 1;
      break;
    case 'e':
      /* if op_mode == 0 the tool encrypts */
      op_mode = 0;
      break;
    case 's':
      /* if op_mode == 2 the tool signs */
      op_mode = 2;
      break;
    case 'v':
      /* if op_mode == 3 the tool verifies */
      op_mode = 3;
      break;
    case 'h':
    default:
      usage();
    }
  }

  /* check arguments */
  check_args(input_file, output_file, password, bit_mode, op_mode);

  /* TODO Develop the logic of your tool here... */
  int sizesForModes;
    if (bit_mode == 128) {
	  sizesForModes = 16;
  }else{
	  sizesForModes = 32;
  }
 unsigned char key[sizesForModes], iv[sizesForModes];

  /* Initialize the library */

  /* Keygen from password */
	keygen(password, key,iv,bit_mode);
	printf("KEY:\n");
print_hex(key, sizesForModes);//strlen((const char *)key));
	printf("IV:\n");
print_hex(iv, strlen((const char *)iv));

/***************************TESTING*****************************/
unsigned char * ciphertext = malloc(sizesForModes*2);
const unsigned char in[16]= "test me sir";
encrypt_tst(in, 16, key, iv, ciphertext);
	printf("cipher text:\n");
	int cipher_len = strlen((const char *)ciphertext);
print_hex(ciphertext, cipher_len);


unsigned char * plaintext = malloc(7);
decrypt_tst(ciphertext, cipher_len, key, iv, plaintext);
	printf("plain text:\n");
	int plain_len = strlen((const char *)plaintext);
print_string(plaintext, plain_len);

/***************************\/TESTING*****************************/

  /* Operate on the data according to the mode */
  /* encrypt */

  /* decrypt */

  /* sign */

  /* verify */

  /* Clean up */
  free(input_file);
  free(output_file);
  free(password);

  /* END */
  return 0;
}
