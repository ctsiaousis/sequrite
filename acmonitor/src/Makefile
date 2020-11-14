all: logger acmonitor test_aclog

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl -g

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor -g

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog -g

run: logger test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor

