# 是否是vpdn环境
ifeq ($(vpdn), y)
DEFS = -DVPDNLZ
endif

CC = gcc -g -shared
CC2 = g++ -g -shared

#SRC=packet_parser.c vpn.c pptp.c l2tp.c save_info.c flagMask.h packet_parser.h vpn.h pptp.h l2tp.h save_info.h
#LIBS=-lmysqlclient
LIBS=-L$(ORACLE_HOME)/lib/ -lcomlog
ICINCHOME = $(ORACLE_HOME)/rdbms/public/
CFLAGS:= -I./ -I../common/inlcude/ -I$(ICINCHOME)

#all c files at current directory
SRCS_C := $(wildcard *.c)

#replace .cpp to .o in SRCS
OBJS_C := $(SRCS_C:%.c=%.o)

all:$(OBJS_C)
%.o : %.c
	$(CC2) $(CFLAGS) -fPIC -c $< -o $@ $(LIBS)

.PHONY : clean

clean:
	rm -f *.o

