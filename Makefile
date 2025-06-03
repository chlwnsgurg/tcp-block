all: tcp-block

main.o: main.c

block.o: libnet.h block.h block.c

tcp-block: main.o block.o
	gcc -o tcp-block block.o main.o -lpcap

clean:
	rm -f tcp-block *.o
