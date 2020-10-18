CC = gcc

CFLAGS = -Wall -Wformat-security -fPIE -fstack-protector-all \
		 -Wstack-protector --param ssp-buffer-size=4 \
		 -D_FORTIFY_SOURCE=2 -std=c99 -O -g

OFILES = simple_crypto.o demo.o

CFILE = simple_crypto.c demo.c

EXE = demo

all : ${EXE}

${EXE} :
	@$(CC) $(CFLAGS) -o ${EXE} ${CFILE}

clean :
	-rm -f ${OFILES} ${EXE} *~
