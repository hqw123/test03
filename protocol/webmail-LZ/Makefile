# 是否是vpdn环境
ifeq ($(vpdn), y)
DEFS = -DVPDNLZ
endif

CC = gcc -g -shared
CC2 = g++ -g -shared

# Kernel
ifeq (,$(KERNELVER))
KERNELVER=$(shell uname -r)
endif
KERNELDIR = /lib/modules/${KERNELVER}/source/include

INCLUDE = -I$(KERNELDIR) -I/usr/src/PF_RING/userland/lib -I/usr/include/libxml2 -I/usr/local/include -I$(ORACLE_HOME)/rdbms/public/ -I../common/inlcude/
LIBS = -L /usr/lib -L . -L$(ORACLE_HOME)/lib/ -lpthread -lpcre -lz -lxml2 -lobject -lcomlog
#SRCS = webmail.c common.c analyse_sina.c analyse_21cn.c analyse_sohu.c analyse_163.c analyse_hotmail.c analyse_yahoo.c analyse_tom.c analyse_yeah.c analyse_eyou.c analyse_263.c analyse_qq.c analyse_sogou.c analyse_126.c analyse_188.c analyse_gmail.c mail_type.c control.c analyse_mail.c analyse_aol.c analyse_hanmail.c analyse_139.c analyse_m_163.c analyse_m_qq.c analyse_2980.c analyse_189.c 
#OBJS = webmail.o common.o analyse_sina.o analyse_21cn.o analyse_sohu.o analyse_163.o analyse_hotmail.o analyse_yahoo.o analyse_tom.o analyse_yeah.o analyse_eyou.o analyse_263.o analyse_qq.o analyse_sogou.o analyse_126.o analyse_188.o analyse_gmail.o mail_type.o control.o analyse_mail.o analyse_aol.o analyse_hanmail.o analyse_139.o analyse_m_163.o analyse_m_qq.o analyse_2980.o analyse_189.o 
#HEADS = common.h mail_type.h
CFLAGS:= -I./ $(INCLUDE)

#all c files at current directory
SRCS_C := $(wildcard *.c)

#replace .cpp to .o in SRCS
OBJS_C := $(SRCS_C:%.c=%.o)

all: libpktmanage.so $(OBJS_C)

libpktmanage.so:
	cd ofo_3.0; make; make install

%.o : %.c
	$(CC2) $(CFLAGS) -fPIC -c $< -o $@ $(LIBS)
	
.PHONY : clean

clean:
	rm -f *.o
