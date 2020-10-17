CC = gcc

CFLAGS = -Wall -fstack-protector -std=c99 -O0 -g

OFILES = simple_crypto.o demo.o

CFILE = simple_crypto.c demo.c

EXE = demo

all : ${EXE}

${EXE} :
	@$(CC) $(CFLAGS) -o ${EXE} ${CFILE}

clean :
	-rm -f ${OFILES} ${EXE} *~
