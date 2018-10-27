#------------------------------------------------------------------------
# Nodes Monitor System is a sniffer to get evidences on Internet.      
#                                                                       
# Copyright (C) 2008  Information Security Techology CO., Ltd.
# This program belongs to ISTC, which shall not be reproduced,   
# copied, or used in other ways without permission. Otherwise RYing    
# ISTC will have the right to pursue legal responsibilities.            
#
#------------------------------------------------------------------------
#
# Module Name:     Makefile
#
#------------------------------------------------------------------------
# Notes:
#      Makefile for making IM processor to a dynamic linking lib. 
#------------------------------------------------------------------------
# Change Activities:
# tag  Reason   Ver  Rev Date   Origin      Description
# ---- -------- ---- --- ------ ----------- -----------------------------
# $d0= -------- 1.00 001 081126 Zjz Initial
# $d1= -------- 1.01 001 081129 Zjz Add the MSN module
# $d2= -------- 1.02 001 081202 Zjz Add the Net2Phone module
# $d3= -------- 1.03 001 081205 Zjz Add the Yahoo module
# $d4= -------- 1.04 001 081211 Zjz Add the Fetion module
# $d5= -------- 1.05 001 081224 Zjz Add the UC module
# $d6= -------- 1.06 001 081229 Zjz Add the QQ module
#
#------------------------------------------------------------------------

	# 是否是vpdn环境
	ifeq ($(vpdn), y)
	DEFS = -DVPDNLZ
	endif

	#
	# Kernel
	#
	ifeq (,$(KERNELVER))
	KERNELVER=$(shell uname -r)
	endif
	KERNELDIR = /lib/modules/${KERNELVER}/source/include

	#
	# PF_RING
	#
	PFRINGDIR  = /usr/src/PF_RING/userland/lib
	LIBPFRING  = ${PFRINGDIR}/libpfring.a

	#
	# PF_RING aware libpcap
	#
	PCAPDIR    = /usr/src/PF_RING/userland/libpcap-1.0.0-ring
	LIBPCAP    = ${PCAPDIR}/libpcap.a

	#
	# ORACLE occi
	#
	ICINCHOME    = $(ORACLE_HOME)/rdbms/public/
	ICLIBHOME    = $(ORACLE_HOME)/lib/
	
	#
	# Search directories
	#
	INCLUDE    = -I${KERNELDIR} -I${PFRINGDIR} -I${PCAPDIR} -I/usr/include/libxml2 -I${ICINCHOME} -I../common/inlcude/

	# C compiler and flags
	CC         = g++ 
	CFLAGS     = -g -Wall ${INCLUDE} $(DEFS) -fPIC

	# Make command
	MAKE       = make -w
	MAKECLEAN  = make clean

	# Main targets
	OBJS  = IsIm.o BaseFileExtractor.o PopExtractor.o PopSession.o DampedMap.o XmlStorer.o Public.o PacketInfo.o BaseTextExtractor.o \
	FetionTextExtractor.o AndroidFetionTextExtractor.o SkypeTextExtractor.o MSNTextExtractor.o YahooTextExtractor.o QQMsgExtractor.o util.o md5.o qqcrypt.o \
	QQFileExtractor.o GambleAccountExtractor.o WangwangTextExtractor.o GtalkTextExtractor.o AndroidMiliaoTextExtractor.o AndroidWeixinTextExtractor.o AndroidQQTextExtractor.o \
	AndroidMomoTextExtractor.o AndroidQtalkTextExtractor.o AndroidYYTextExtractor.o AndroidTangoTextExtractor.o AndroidCocoTextExtractor.o AndroidKuaiyaTextExtractor.o\
	AndroidTalkboxTextExtractor.o AndroidHiTextExtractor.o AndroidVoxerTextExtractor.o AndroidWhatsappTextExtractor.o AndroidZelloTextExtractor.o AndroidTelegramTextExtractor.o \
	AndroidSkypeTextExtractor.o AndroidBBMTextExtractor.o AndroidKaKaotalkTextExtractor.o AndroidOovooTextExtractor.o AndroidZaloTextExtractor.o AndroidAireTalkTextExtractor.o \
	AndroidNimbuzzTextExtractor.o AndroidLineTextExtractor.o AndroidViberTextExtractor.o AndroidDropboxTextExtractor.o AndroidKeechatTextExtractor.o
#       FileStream.o    
#N2PTextExtractor.o UCTextExtractor.o UCCrypt.o QQTextExtractor.o Occi.oVoipExtractor.o  VoiceSession.o GameExtractor.o BaseGameExtractor.o RtpParser.o QQFileExtractor.o MSNFileExtractor.o

	# How to make an object file
%.o:%.cpp
	@echo ""
	@echo "=*= making object $@ =*="
	${CC} ${CFLAGS} -c $< -o $@

im.a: ${OBJS}
	@echo ""
	@echo "=*= making library $@ =*="
	ar rc $@ ${OBJS}
	ranlib $@

clean:
	@echo ""
	@echo "=*= make clean =*="
	@rm -f im.a *.o *~ core.*
	@rm -f /usr/lib/libisim.so

# End of file
