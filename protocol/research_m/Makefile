# 是否是vpdn环境
ifeq ($(vpdn), y)
DEFS = -DVPDNLZ
endif

LIBS   = -L$(ORACLE_HOME)/lib/ -lcomlog
ICINCHOME = $(ORACLE_HOME)/rdbms/public/
INCPATH = -I../common/inlcude/ -I$(ICINCHOME)

all:
	g++ $(DEFS) -c $(INCPATH) $(LIBS) -Wall -fPIC Research_m.cpp UserAgent_m.cpp
	ar -r libResearchm.a Research_m.o UserAgent_m.o
clean:
	rm -rf *.a *.o *~
