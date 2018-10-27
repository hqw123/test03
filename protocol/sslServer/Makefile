CC1    = gcc -g
SLIBS  = libSentinelKeys32.a
LIBS   = -lsslServer -lxml2 -lssl -lpthread -lpcre
TARGET = sslServer
#httpsServerL

$(TARGET): Tmain.c libsslServer.so
	$(CC1) -o $@ Tmain.c $(LIBS) $(SLIBS)
#	cp -f libsslServer.so /usr/lib

libsslServer.so:proxyUnit.c  dnsServer.c fakeClient.c fakeServerB.c  fakeSocket.c  serverInfo.c opsRegister.c dataProcessorB.c listenSSL.c req_filter.c
	$(CC1) -fPIC -shared -o $@ $^
	cp -f libsslServer.so /usr/lib
	cp -f libsslServer.so ../lib

clean: 
	rm -f sslServer *.so *.o *~
