all:	sniffer

OPTS:	-W

sniffer: main.c header.h hex.h tlsparser.h  decryptcomparator.c decryptcomparator_server.c decrypt.c decrypt.h hex.h
	gcc $(OPTS) -o sniffer main.c decryptcomparator_server.c decryptcomparator.c decrypt.c decrypt.h hex.h header.h tlsparser.h hex.h -lpcap -lgcrypt


clean:
	rm -f sniffer
	rm -f core
	rm -f core.*
