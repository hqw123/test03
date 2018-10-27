# 是否是vpdn环境
ifeq ($(vpdn), y)
DEFS = -DVPDNLZ
endif

CC = gcc -g -shared
CC2 = g++ -g -shared -O2

# Kernel
ifeq (,$(KERNELVER))
KERNELVER=$(shell uname -r)
endif
KERNELDIR = /lib/modules/${KERNELVER}/source/include

INCLUDE = -I$(KERNELDIR) -I/usr/src/PF_RING/userland/lib -I/usr/include/libxml2 -I/usr/local/include -I$(ORACLE_HOME)/rdbms/public/ -I../common/inlcude/
LIBS = -L /usr/lib -L . -L$(ORACLE_HOME)/lib/ -lpthread -lpcre -lz -lxml2 -lobject -lcomlog
CFLAGS:= -I./ $(INCLUDE)

#all c files at current directory
SRCS_C := $(wildcard *.c)

#replace .c to .o in SRCS
OBJS_C := $(SRCS_C:%.c=%.o)

all: $(OBJS_C)

%.o : %.c
	$(CC2) $(CFLAGS) -fPIC -c $< -o $@ $(LIBS)
	
.PHONY : clean

clean:
	rm -f *.o