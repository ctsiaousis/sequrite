CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = main.o rsa.o utils.o
LIBS := -lm

TARGET = rsa_tool


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) $(DBG) -o $(TARGET) $(OBJFILES) $(LIBS)

clean:
	rm -f $(TARGET) *.o
