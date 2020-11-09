#include "utils.h"
#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
 */
void print_hex(unsigned char *data, size_t len) {
  size_t i;

  if (!data)
    printf("NULL data\n");
  else {
    for (i = 0; i < len; i++) {
      if (!(i % 16) && (i != 0))
        printf("%02X ", data[i]);
      printf("%02X ", data[i]);
    }
    printf("\n");
  }
}

/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
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
 */
void usage(void) {
  printf("\n"
         "Usage:\n"
         "    ./rsa_tool -g \n"
         "    ./rsa_tool -i in_file -o out_file -k key_file [-d | -e]\n"
         "    ./rsa_tool -h\n");
  printf("\n"
         "Options:\n"
         " -i    path    Path to input file\n"
         " -o    path    Path to output file\n"
         " -k    path    Path to key file\n"
         " -d            Decrypt input and store results to output\n"
         " -e            Encrypt input and store results to output\n"
         " -g            Generates a keypair and saves to 2 files\n"
         " -v            Verbose output.\n"
         " -h            This help message\n");
  exit(EXIT_FAILURE);
}

/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void check_args(char *input_file, char *output_file, char *key_file,
                int op_mode) {
  if ((!input_file) && (op_mode != 2)) {
    printf("Error: No input file!\n");
    usage();
  }

  if ((!output_file) && (op_mode != 2)) {
    printf("Error: No output file!\n");
    usage();
  }

  if ((!key_file) && (op_mode != 2)) {
    printf("Error: No user key!\n");
    usage();
  }

  if (op_mode == -1) {
    printf("Error: No mode\n");
    usage();
  }
}


/**
 * Reads a file returning a size_t array
 */
void *readFile(char *path, size_t *size, TYPE t) {
  FILE *fileptr;
  void *buffer;
  size_t filelen;

  if( access(path, F_OK) == -1){
    printf("Seems that file does not exist.\n");
    exit(-1);
  }
  fileptr = fopen(path, "rb"); // Open the file in binary mode

  fseek(fileptr, 0, SEEK_END); // Jump to the end of the file
  filelen = ftell(fileptr);    // Get the current byte offset in the file
  rewind(fileptr);             // Jump back to the beginning of the file
  
  switch(t){
        case UCHAR:
            buffer = (unsigned char*)malloc((filelen) * sizeof(unsigned char));
            fread(buffer, filelen, sizeof(unsigned char), fileptr); // Read in the entire file
            break;
        case SIZE_T:
            buffer = (size_t*)malloc((filelen) * sizeof(size_t));
            fread(buffer, filelen, sizeof(size_t), fileptr);
            break;
        default:
            printf("wrong type call.\n");
            break;
    }


  fclose(fileptr);                    // Close the file


  *size = filelen;
  return buffer;
}

/**
 * Writes a size_t array to a file
 */
void writeFile(char *path, void *buff, size_t size, TYPE t) {
  FILE *f = fopen(path, "w");

  switch(t){
        case UCHAR:
              if (size > fwrite(buff, sizeof(unsigned char), size, f))
    printf("error writing file...\n");
            break;
        case SIZE_T:
              if (size > fwrite(buff, sizeof(size_t), size, f))
    printf("error writing file...\n");
            break;
        default:
            printf("wrong type call.\n");
            break;
    }

  fclose(f);
}

/**
 * Returns a pseudo random integer
 */
int getRandom(int thresh) {
  if( isVerbose() )
    printf("\npseudorandom : %d\n", (int)random()%thresh);
  return (int)random()%thresh;
}
