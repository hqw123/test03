# 是否是vpdn环境
ifeq ($(vpdn), y)
DEFS = -DVPDNLZ
endif

LIBS   = -L$(ORACLE_HOME)/lib/ -lcomlog
ICINCHOME = $(ORACLE_HOME)/rdbms/public/
INCPATH = -I../common/inlcude/ -I$(ICINCHOME)

all:
	g++ $(DEFS) -c $(INCPATH) $(LIBS) -Wall -fPIC Research.cpp AvResearcher.cpp ImeResearcher.cpp UserAgent.cpp QQVersion.cpp
	ar -r libResearch.a Research.o AvResearcher.o ImeResearcher.o UserAgent.o QQVersion.o
clean:
	rm -rf *.a *.o
