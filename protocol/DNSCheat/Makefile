CC      = g++
CFLAGS  = -g -Wall
INCLUDE = -I/usr/local/include -I/usr/include/libxml2 -I../common/inlcude/
LIBS    = -L /usr/lib -L . -lboost_regex -lssl -lpcap -lpthread -lnet -lxml2 
OBJS  = PacketParser.o  Public.o DNSSpoof.o siteSwitch.o DNSserver.o

all: DNSCheat

DNSCheat:  libdns.so $(OBJS)
	$(CC) $(CFLAGS) -o DNSCheat main.cpp $(INCLUDE)  $(OBJS) libdns.so $(LIBS)

libdns.so:
	gcc -fPIC -I$(INCLUDE) -shared -o libdns.so DNSutil.c
	rm -f /usr/lib/libdns.so
	cp libdns.so /usr/lib/
	cp libdns.so ../lib/
	
%.o: %.c
	$(CC) $(CFLAGS) -c $(INCLUDE) $<

%.o: %.cpp
	$(CC) $(CFLAGS) -c $(INCLUDE) $<
	
clean:
	rm -f DNSCheat *.o *.so *~