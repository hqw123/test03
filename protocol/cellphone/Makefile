# 是否是vpdn环境
ifeq ($(vpdn), y)
DEFS = -DVPDNLZ
endif

ICINCHOME=$(ORACLE_HOME)/rdbms/public/
ICLIBHOME=$(ORACLE_HOME)/lib/
ICLIBPATH=-L$(ICLIBHOME) -lcomlog
OCCILIB=$(ICLIBPATH)
#OBJS=clue.o clue_c.o Public.o
CFLAGS:= -I./ -I../common/inlcude/ -I$(ICINCHOME) -I/usr/include/libxml2

CC2 = g++ -g -shared -O2
	
#all c files at current directory
SRCS_CPP := $(wildcard *.cpp)

#replace .cpp to .o in SRCS
OBJS := $(SRCS_CPP:%.cpp=%.o)

all:$(OBJS)
%.o : %.cpp
	$(CC2) $(CFLAGS) -fPIC -c $< -o $@ $(OCCILIB)
	
.PHONY : clean

clean:
	rm -f *.o