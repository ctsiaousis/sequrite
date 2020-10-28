CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
LIBSSL = -lssl -lcrypto

TARGETS = ssl_tool


all: $(TARGETS)

ssl_tool: ssl_tool.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

clean:
	rm -f $(TARGETS)
