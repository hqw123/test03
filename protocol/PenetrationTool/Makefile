#------------------------------------------------------------------------
# Nodes Monitor System is a sniffer to get evidences on Internet.      
#                                                                       
# Copyright (C) 2010 BaiHong Information Security Techology CO., Ltd.
# This program belongs to BaiHong ISTC, which shall not be reproduced,   
# copied, or used in other ways without permission. Otherwise BaiHong    
# ISTC will have the right to pursue legal responsibilities.            
#
#------------------------------------------------------------------------
#
# Module Name:     Makefile
#
#------------------------------------------------------------------------
# Notes:
#      Makefile for making PenetrationTool processor to a dynamic linking lib. 
#------------------------------------------------------------------------
# Change Activities:
# tag  Reason   Ver  Rev Date   Origin      Description
# ---- -------- ---- --- ------ ----------- -----------------------------
# $d0= -------- 1.00 001 100507 tz Initial
# $d1= -------- 1.01 001 100507 tz Add the UnBoundedExtractor module
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
	OBJS  = IsTools.o XmlStor.o Public.o PacketInfo.o BaseToolsExtractor.o PenetrationToolExtractor.o

	# How to make an object file
%.o:%.cpp
	@echo ""
	@echo "=*= making object $@ =*="
	${CC} ${CFLAGS} -c $< -o $@

penetration.a: ${OBJS}
	@echo ""
	@echo "=*= making library $@ =*="
	ar rc $@ ${OBJS}
	ranlib $@

clean:
	@echo ""
	@echo "=*= make clean =*="
	@rm -f penetration.a *.o *~ core.*
	@rm -f /usr/lib/libisTool.so

# End of file
