#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include  <fcntl.h>         /* open */

typedef enum {
    UCHAR,
    SIZE_T
} TYPE;
/*
 * Prints the hex value of the input, 16 values per line
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *, size_t);


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *, size_t);


/*
 * Prints the usage message
 */
void
usage(void);


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *, char *, char *, int);

void *readFile(char *, size_t*, TYPE);


void writeFile(char* , void*, size_t, TYPE);

int getRandom(int);
#endif /* _UTILS_H */
