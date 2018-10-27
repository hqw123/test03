# 编译标准LZ
# make
#
# 编译标准LZ-vpdn
# make vpdn=y
#
# 编译千兆LZ
# make glz=y
#
# 编译千兆LZ-vpdn
# make glz=y vpdn=y
#
# 如果需要验证加密狗, 需要设置check=y
# make check=y
# make vpdn=y check=y
# make glz=y check=y
# make glz=y vpdn=y check=y
#
# 由于版本之间的差异, 为了编译的顺利, 可能需要更多的使用make clean
# make clean
#
# 关于boost的库, 不同版本的库对应不同的库名, 
# boost-1.33.1版本对应链接：-lboost_regex-gcc, -lboost_thread-gcc-mt
# boost-1.46.1版本对应链接：-lboost_regex, -lboost_thread
#

ICINCHOME=$(ORACLE_HOME)/rdbms/public/
OCCILIB=-L$(ORACLE_HOME)/lib/ -lm -locci -lclntsh

INCLUDE = -I/usr/local/include -I/usr/include/libxml2 -I$(ICINCHOME) -I./common/inlcude/
LIBS    = -L /usr/local/lib -L . $(OCCILIB) -lboost_regex -lboost_filesystem -lssl -lpcap -lpthread -lnet -lxml2 -lpcre -lpktmanage -lcomlog
LIBSA =  im/im.a PenetrationTool/penetration.a webim/webim.a websns/websns.a research/libResearch.a research_m/libResearchm.a 
OBJS  = PacketParser.o ring_util.o analyse_smtp.o PublicOcci.o PublicDb.o Public.o http_get.o analyse_FTP.o analyse_pppoe.o analyse_telnet.o db_data.o msg_queue.o cJSON.o analyse_domain.o
SUBDIRS = object account im PenetrationTool research research_m webim webmail-LZ websns pptp weibo talkspace onlineproxy blog rmcontrol p2p website cellphone md5
COMMON_DIRS = object account webmail-LZ pptp weibo talkspace onlineproxy blog rmcontrol p2p website cellphone md5

CC = gcc -g -shared
CC2 = g++ -g -shared

# 是否是vpdn环境
ifeq ($(vpdn), y)
DEFS = -DVPDNLZ
endif

# 是否是千兆LZ
ifeq ($(glz), y)
ANALYZER_SRC = Analyzer-glz.cpp
LIBS += -lboost_thread
else
ANALYZER_SRC = Analyzer.cpp
LIBS += -lboost_thread
endif

# 是否要验证加密狗
ifeq ($(check), y)
DEFS += -DCHECK
endif

CFLAGS  = -Wall
CFLAGS += -fPIC
CFLAGS += $(DEFS)
CFLAGS += -O2

TARGETA = libanalyzeServer.so

all: subdirs $(TARGETA)

subdirs:
	for dir in $(SUBDIRS); \
	do \
		make -C $$dir || exit "$$?"; \
	done

$(TARGETA):	$(OBJS) $(ANALYZER_SRC)
	$(CC2) $(CFLAGS) $(INCLUDE) -o $@ $(wildcard $(addsuffix /*.o, $(COMMON_DIRS))) $^ $(LIBSA) $(LIBS)
	cp -f $@ /usr/local/lib/
	
%.o: %.c
	$(CC2) $(CFLAGS) -c $(INCLUDE) $<

%.o: %.cpp
	$(CC2) $(CFLAGS) -c $(INCLUDE) $<

clean:
	rm -f *.o *.so *~
	rm -f /usr/local/lib/$(TARGETA)

cleanall:
	for dir in $(SUBDIRS); \
	do \
		make clean -C $$dir; \
	done
	rm -f *.o *.so *~
	rm -f /usr/local/lib/$(TARGETA)
