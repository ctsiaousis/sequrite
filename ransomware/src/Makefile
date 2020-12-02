all: logger acmonitor test_aclog openSSLlogger

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl -g

openSSLlogger: logger.c
	gcc -Wall -D_FILE_OFFSET_BITS=64 -fPIC -shared -o openSSLlogger.so logger.c -lcrypto -ldl -g

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor -g

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog -g
clean:
	rm -rf logger.so
	rm -rf acmonitor
	rm -rf testFiles
	rm -rf test_aclog
	rm -rf openSSLlogger.so
