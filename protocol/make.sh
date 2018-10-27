#!/bin/sh
echo $LD_LIBRARY_PATH | grep -e './lib' 1> /dev/null
ret1=$?
echo $LD_LIBRARY_PATH | grep -e '/home/jacky.\+pro.\+lib' 1> /dev/null
ret2=$?

if [ $ret1 -eq 0 ] || [ $ret2 -eq 0 ];then
	echo "library configuration is ok"
else
	echo "reset the library configuration"
	source /etc/profile
	export LD_LIBRARY_PATH="$LD_LIBRARY_PATH:./lib"
fi

make $1 -f Makefile
