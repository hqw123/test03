# 是否是vpdn环境
ifeq ($(vpdn), y)
DEFS = -DVPDNLZ
endif

CC  = gcc -g -shared
CC2 = g++ -g -shared

LIBS   = -L$(ORACLE_HOME)/lib/ -lcomlog
ICINCHOME = $(ORACLE_HOME)/rdbms/public/
#FILES  = accountGeterL.c storeEngineL.c
#FILES2 = HttpPostEntranceL.cpp HttpPostL.cpp
CFLAGS:= -I./ -I../common/inlcude/ -I$(ICINCHOME) -O2

#all c files at current directory
SRCS_CPP := $(wildcard *.cpp)
SRCS_C := $(wildcard *.c)

#replace .cpp to .o in SRCS
OBJS_CPP := $(SRCS_CPP:%.cpp=%.o)
OBJS_C := $(SRCS_C:%.c=%.o)

all:$(OBJS_CPP) $(OBJS_C)
%.o : %.cpp
	$(CC2) $(CFLAGS) -fPIC -c $< -o $@ $(LIBS)

%.o : %.c
	$(CC2) $(CFLAGS) -fPIC -c $< -o $@ $(LIBS)

.PHONY : clean

clean:
	rm -f *.o