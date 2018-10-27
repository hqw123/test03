#!/bin/sh

echo "Please refer to networkcard, eth0...eth1 "
read device

./webmail $device >> log.txt 2>&1 &
sleep 1
mainprocess=$(ps -e | grep webmail)
if [ -z "$mainprocess" ]; then
    echo "start webmail error, perhaps the argument passed to webmail is invalid. please try again"
    exit 2
fi

if [ -e DeviceInfo.xml ]
then
	echo "found DeviceInfo.xml"
else
	touch DeviceInfo.xml
fi

trap 'killall -s SIGINT webmail; exit 1' SIGINT

atime=$(ls --full-time DeviceInfo.xml | awk '{print $6 $7}')

while [ -e DeviceInfo.xml ]
do
    ./devstatus &
	aatime=$(ls --full-time DeviceInfo.xml | awk '{print $6 $7}')
	if [ "$aatime" != "$atime" ]; then
		echo "The configure file has been updated, now restart webmail"
		mainprocess=$(ps -e | grep webmail)
		if [ -n "$mainprocess" ]; then
			killall -s SIGINT webmail
		fi
		./webmail $device >> log.txt 2>&1 &
		atime=${aatime}
	else
		mainprocess=$(ps -e | grep webmail)
		if [ -z "$mainprocess" ]; then
			echo "The webmail has been exited, now restart it!"
			./webmail $device >> log.txt 2>&1 & 
		fi
	fi
	sleep 60
done
