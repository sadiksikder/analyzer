all:	sniffer

OPTS:	-W

sniffer: main.c header.h hex.h tlsparser.h 
	gcc $(OPTS) -o sniffer main.c header.h tlsparser.h hex.h -lpcap


clean:
	rm -f sniffer
	rm -f core
	rm -f core.*
