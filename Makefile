LDLIBS=-lpcap

all: tcp-block

mac.o: mac.h mac.cpp

main.o: libnet.h main.cpp

block.o: libnet.h block.h block.cpp

tcp-block: main.o block.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@
clean:
	rm -f tcp-block *.o