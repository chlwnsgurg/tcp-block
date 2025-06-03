all: tcp-block

mac.o: mac.h mac.cpp

ip.o: ip.h ip.cpp

main.o: libnet.h util.h main.cpp

block.o: libnet.h block.h block.c

tcp-block: main.o mac.o ip.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean: rm -f tcp-block *.o