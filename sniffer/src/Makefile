all: monitor #logger acmonitor test_aclog openSSLlogger

monitor: 
	gcc -O2 -Wall -pedantic -lpcap monitor.c -o monitor -g

clean:
	rm -rf exa
	rm -rf monitor
