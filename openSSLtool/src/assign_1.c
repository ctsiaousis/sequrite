#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/cmac.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>

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
void handleErrors(void);
EVP_PKEY *returnKeyStructure(unsigned char *, int);
int nextTimes16(int);

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
  int mode = bit_mode / 8;

  /* Create and initialise the context */
  EVP_CIPHER_CTX *ctx;
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Gen key & IV for AES 128/256 ECB mode. A SHA1 digest is used to hash the
   * supplied key material.
   *
   * NOTE: EVP_BytesToKey returns the size of key in BYTES!!!
   *
   * ECB mode should not produce an IVector. That is the case with our calls
   * EVP_aes_256/128_ecb(). If we were to use CBC we would also produce an IV.
   * Take a look on the README reference links. =)
   */
  if (mode !=
      EVP_BytesToKey((mode == 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb(),
                     EVP_sha1(), NULL, password, strlen((const char *)password),
                     1, key, iv))
    handleErrors();
}

/*
 * Encrypts the data
 */
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
             unsigned char *iv, unsigned char *ciphertext, int bit_mode) {

  /* TODO Task B */
  int mode = bit_mode / 8;
  int ciphertext_len = 0;
  int len;

  /* Create and initialise the context */
  EVP_CIPHER_CTX *ctx;
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /*
   * Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits
   */
  if (1 != EVP_EncryptInit_ex(
               ctx, (mode >= 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb(), NULL,
               key, iv))
    handleErrors();

  /*
   * Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
   ecrypt:
  if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len += len;
  // if(len < plaintext_len){
    // printf("I encrypted less.%d\n", ciphertext_len);
    // goto ecrypt;
  // }

  /*
   * Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    handleErrors();

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
}

/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext, int bit_mode) {
  int plaintext_len;

  plaintext_len = 0;

  /*TODO Task C */
  EVP_CIPHER_CTX *ctx;

  int mode = bit_mode / 8;

  int len = 0;

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
  if (1 != EVP_DecryptInit_ex(
               ctx, (mode >= 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb(), NULL,
               key, iv))
    handleErrors();

  /*
   * Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary.
   */
   dcrypt:
  if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len += len;
  if(plaintext_len < ciphertext_len-16){
    printf("jump\n");
    goto dcrypt;
  }

  // if (1 != EVP_DecryptFinal_ex(ctx, plaintext, &len))
    // handleErrors();

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

/*
 * Generates a CMAC
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key,
              unsigned char *cmac, int bit_mode) {

  /* TODO Task D */
  size_t req = 0;

  if (!data || !key)
    return;
  /*Determine bit mode*/
  int mode = (bit_mode == 128) ? 16 : 32;

  /*Create CMAC Key*/
  EVP_PKEY_CTX *kctx;
  if (!(kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, NULL)))
    handleErrors();

  /*Init CMAC Key*/
  if (!EVP_PKEY_keygen_init(kctx))
    handleErrors();

  /*Determine Cipher Based on Mode*/
  const EVP_CIPHER *ciph = (mode >= 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb();

  /* Set the cipher to be used for the CMAC */
  if (EVP_PKEY_CTX_ctrl(kctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_CIPHER, 0,
                        (void *)ciph) <= 0)
    handleErrors();

  /* Set the key data to be used for the CMAC */
  if (EVP_PKEY_CTX_ctrl(kctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_MAC_KEY,
                        mode, key) <= 0)
    handleErrors();

  /* Generate the key */
  EVP_PKEY *wrappedKey =
      EVP_PKEY_new(); // =EVP_PKEY_new_mac_key(EVP_PKEY_CMAC, NULL, key, mode);
  if (!EVP_PKEY_keygen(kctx, &wrappedKey))
    handleErrors();

  /*Create MD context*/
  EVP_MD_CTX *ctx = NULL;
  if (!(ctx = EVP_MD_CTX_new()))
    handleErrors();

  /*Init digestion process using the created MD_CTX with SHA1, KKEY_CTX with the
   * created KEY*/
  if (1 != EVP_DigestSignInit(ctx, &kctx, EVP_sha1(), NULL, wrappedKey))
    handleErrors();

  /*Load the data of the message*/
  if (1 != EVP_DigestSignUpdate(ctx, data, data_len))
    handleErrors();

  /* Finalise */
  if (1 != EVP_DigestSignFinal(ctx, NULL, &req))
    handleErrors();

  // cmac = OPENSSL_malloc(req);
  if (cmac == NULL)
    handleErrors();

  if (1 != EVP_DigestSignFinal(ctx, cmac, &req))
    handleErrors();

  // print_hex(data, strlen(data));//data_len+req);
  // printf("\n");
  // print_hex(cmac, strlen(cmac));//req);

  CMAC_CTX_free(ctx);

  return;
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

unsigned char *readFile(char *path) {
  FILE *f = fopen(path, "rb");
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  unsigned char *buff;
  buff = malloc(fsize + 1);
  fread(buff, 1, fsize, f);
  fclose(f);

  buff[fsize] = 0;
  return buff;
}

void writeFile(char *path, unsigned char* buff, int size) {
  FILE *f = fopen(path, "wb");

  fwrite(buff, 1, size, f);
  fclose(f);
}

int nextTimes16(int in){
  printf("infunc: %d\n",in);
  int i = in;
  for(i = in; i < in+16; i++){
    if( (in % 16) == 0){
      printf("retfunc: %d\n",in);
      return in;
    }
    in++;
  }
  return 0;
}

void concatBuffers(unsigned char * in1, int len1,
                              unsigned char * in2, int len2,
                              unsigned char * out)
{
  unsigned char *temp;
  int i;

  for(i = 0; i < len1; i++){
    out[i] = in1[i];
  }
  for(i = 0; i < len2; i++){
    out[len1+i] = in2[i];
  }
}

EVP_PKEY *returnKeyStructure(unsigned char *key, int mode) {
  /*Create CMAC Key*/
  EVP_PKEY_CTX *kctx;
  if (!(kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_CMAC, NULL)))
    handleErrors();

  /*Init CMAC Key*/
  if (!EVP_PKEY_keygen_init(kctx))
    handleErrors();

  /*Determine Cipher Based on Mode*/
  const EVP_CIPHER *ciph = (mode >= 32) ? EVP_aes_256_ecb() : EVP_aes_128_ecb();

  /* Set the cipher to be used for the CMAC */
  if (EVP_PKEY_CTX_ctrl(kctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_CIPHER, 0,
                        (void *)ciph) <= 0)
    handleErrors();

  /* Set the key data to be used for the CMAC */
  if (EVP_PKEY_CTX_ctrl(kctx, -1, EVP_PKEY_OP_KEYGEN, EVP_PKEY_CTRL_SET_MAC_KEY,
                        mode, key) <= 0)
    handleErrors();

  /* Generate the key */
  EVP_PKEY *wrappedKey =
      EVP_PKEY_new(); // =EVP_PKEY_new_mac_key(EVP_PKEY_CMAC, NULL, key, mode);
  if (!EVP_PKEY_keygen(kctx, &wrappedKey))
    handleErrors();

  return wrappedKey;
}

int verify_it(const unsigned char *msg, size_t mlen, const unsigned char *val,
              size_t vlen, EVP_PKEY *pkey) {
  /* Returned to caller */
  int result = 0;
  EVP_MD_CTX *ctx = NULL;
  unsigned char buff[EVP_MAX_MD_SIZE];
  size_t size;

  if (!msg || !mlen || !val || !vlen || !pkey)
    return 0;

  ctx = EVP_MD_CTX_new();
  if (ctx == NULL) {
    printf("EVP_MD_CTX_create failed, error 0x%lx\n", ERR_get_error());
    goto err;
  }

  if (1 != EVP_DigestSignInit(ctx, NULL, EVP_sha1(), NULL, pkey)) {
    printf("EVP_DigestSignInit failed, error 0x%lx\n", ERR_get_error());
    goto err;
  }

  if (1 != EVP_DigestSignUpdate(ctx, msg, mlen)) {
    printf("EVP_DigestSignUpdate failed, error 0x%lx\n", ERR_get_error());
    goto err;
  }

  size = sizeof(buff);
  if (1 != EVP_DigestSignFinal(ctx, buff, &size)) {
    printf("EVP_DigestSignFinal failed, error 0x%lx\n", ERR_get_error());
    goto err;
  }

  result = (vlen == size) && (CRYPTO_memcmp(val, buff, size) == 0);
err:
  EVP_MD_CTX_free(ctx);
  return result;
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
  int sizesForModes = bit_mode/8;

  /* Initialize the library */
  unsigned char key[sizesForModes], iv[16];
  unsigned char *input_buff = readFile(input_file);
  int in_file_len = strlen((const char *)input_buff);
  print_string(input_buff, in_file_len);//(bit_mode==128)?nextTimes16(in_file_len):nextTimes16(in_file_len)+16;
  printf("%d\n",sizesForModes);

  /* Keygen from password */
  keygen(password, key, iv, bit_mode);
  printf("KEY:\n");
  print_hex(key, sizesForModes); // strlen((const char *)key));
  printf("IV:\n");
  print_hex(iv, strlen((const char *)iv));

  EVP_PKEY *newKey = returnKeyStructure(password, sizesForModes);
  /***************************TESTING*****************************/


  // unsigned char * ciphertext_new = malloc(sizesForModes+16);
  // EVP_PKEY *newKey = returnKeyStructure(key, sizesForModes);
  // int i = verify_it(ciphertext, sizesForModes, cmac, cmac_len, newKey);
  // printf("verify_it: %d\n", i);

  // writeFile(output_file, plaintext, plain_len);
  // int cmac_len = strlen((const char *)cmac);
  // print_hex(cmac, cmac_len);

  /***************************\/TESTING*****************************/

  /* Operate on the data according to the mode */


  /* encrypt */
  /* if op_mode == 0 the tool encrypts */
  if( op_mode == 0 ){
      int ciph_buf_len = nextTimes16(in_file_len);
      unsigned char *ciphertext = malloc(ciph_buf_len);

      encrypt(input_buff, in_file_len, key, iv, ciphertext, bit_mode);
      printf("cipher text:\n");
      print_hex(ciphertext, ciph_buf_len);

      print_string(ciphertext, ciph_buf_len);

      writeFile(output_file, ciphertext, ciph_buf_len);
      free(ciphertext);
  }

  /* decrypt */
  /* if op_mode == 1 the tool decrypts */
  else if( op_mode == 1 ){
      unsigned char *plaintext = malloc(in_file_len);

      decrypt(input_buff, in_file_len, key, iv, plaintext, bit_mode);
      printf("plain text:\n");
      int plain_len = strlen((const char *)plaintext);
      print_string(plaintext, plain_len);

      writeFile(output_file, plaintext, plain_len);
      free(plaintext);
  }
  /* sign */
  /* if op_mode == 2 the tool signs */
  else if( op_mode == 2 ){
      unsigned char *cmac = OPENSSL_malloc(sizesForModes);

      //encrypt
      int ciph_buf_len = nextTimes16(in_file_len) + 16;
      unsigned char *ciphertext = malloc(ciph_buf_len);
      encrypt(input_buff, in_file_len, key, iv, ciphertext, bit_mode);
      printf("encrypted:\n");
      print_hex(ciphertext, ciph_buf_len);

      // generate
      gen_cmac(ciphertext, ciph_buf_len, key, cmac, bit_mode);
      int cmac_len = strlen(cmac);
      printf("CMAC sign:\n");
      print_hex(cmac, cmac_len);
      unsigned char * newText = malloc(cmac_len+ciph_buf_len);
      concatBuffers(ciphertext, ciph_buf_len, cmac, cmac_len, newText);


      printf("to file:\n");
      print_hex(newText, cmac_len+ciph_buf_len);
      writeFile(output_file, newText, cmac_len+in_file_len);
      
      free(ciphertext);
      free(newText);
      OPENSSL_free(cmac);
  }
  /* verify */
  /* if op_mode == 3 the tool verifies */
  else if( op_mode == 3 ){
      // EVP_PKEY *newKey = returnKeyStructure(key, sizesForModes);
      // unsigned char *plaintext = malloc(in_file_len);

      // decrypt(input_buff, in_file_len, key, iv, plaintext, bit_mode);
      // printf("plain text:\n");
      // int plain_len = strlen((const char *)plaintext);
      // print_string(plaintext, plain_len);


      // int i = verify_it(plaintext, plain_len, cmac, cmac_len, newKey);
      // printf("verify_it: %d\n", i);

      // writeFile(output_file, plaintext, plain_len);
      // int cmac_len = strlen((const char *)cmac);
      // print_hex(cmac, cmac_len);
  }

  /* Clean up */
  free(input_file);
  free(output_file);
  free(password);

  /* END */
  return 0;
}
