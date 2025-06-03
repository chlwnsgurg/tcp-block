all: tcp-block

main.o: util.h main.cpp

mac.o: mac.h mac.cpp

ip.o: ip.h ip.cpp

block.o: libnet.h block.h block.c mac.o ip.o

tcp-block: main.o block.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f tcp-block *.o