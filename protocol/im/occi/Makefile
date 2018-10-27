#/bin/make
###############################################################################
#                       Make file for OCI,OCCI and ODBC demos
###############################################################################
#  Usage :
# For compiling & linking the cdemo81.c file
#    make -f demo_xe.mk buildoci CDEMOEXE=cdemo81 CDEMOOBJS=cdemo81.o 
#
# For compiling & linking the occidml.cpp
#    make -f demo_xe.mk buildocci EXE=occidml OBJS=occidml.o
#
# For compiling & linking the occiobj.cpp
#    make -f demo_xe.mk occiobj 
#
# For compiling & linking ODBCDEMOS
#     make -f demo_xe.mk buildodbcdemo 
#     ODBCDM_HOME=<path where unix driver manager is installed> 
#     ODBCDEMOOBJS=odbcdemo.o ODBCDEMOEXE=odbcdemo 
#
# In general, for any occi program
#    make -f demo_xe.mk buildocci EXE=<exename> OBJS="<list of dependent objs>"
#
# For compiling all demos
#    make -f demo_xe.mk
#
# NOTE: Please change cc and CC to point to the appropiate location on your
#       machine.
#
###############################################################################


ICINCHOME=$(ORACLE_HOME)/rdbms/public/
ICLIBHOME=$(ORACLE_HOME)/lib/
ICLIBPATH=-L$(ICLIBHOME)
OCCILIB=$(ICLIBPATH) -lm -locci -lclntsh -lboost_thread-mt
CLINK= -shared
OBJS=oracle.o PublicOcci.o
#LIB=$(ORACLE_HOME)/lib/libocci.so.10.1 $(ORACLE_HOME)/lib/libclntsh.so.10.1 /usr/lib/libboost_thread.a 

# Linux compiler definitions
# 32bit--/usr/lib/libstdc++.so.5   64bit--/usr/lib64/libstdc++.so.5
CC=g++ /usr/lib/libstdc++.so.5

CCFLAGS=-g -fPIC

%.o:%.cpp
	$(CC) -c -I$(ICINCHOME) $(CCFLAGS) $<

liboracle.so:${OBJS}
	${CC} ${CLINK} ${OBJS} ${OCCILIB} -o $@

clean:
	@rm -f liboracle.so *.o *~ core.*
