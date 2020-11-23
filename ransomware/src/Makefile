all: logger acmonitor 

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl -g

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor -g

clean:
	rm -rf logger.so
	rm -rf acmonitor
	rm -rf testFiles
