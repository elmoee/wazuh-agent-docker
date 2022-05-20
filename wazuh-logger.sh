#!/bin/bash

logfile="/var/log/wazuh/stats.log"

# remove log if it exists
if [ -e $logfile ]; then
   rm $logfile
fi

# stdout to log
exec >$logfile

# Update top relative
top -b -d 1 -n 1 > /dev/null

# Start logging stats
trap "exit 0" SIGINT
while true 
do
    date +%s
    # $12=command, $9=%cpu, $10=%mem, $6=mem bytes
    top -b -n1 -w512 | grep -E '%Cpu|wazuh|audit' | awk ' {if(NR==1) print "total cpu: "100-$8; else {n = split($12, arr, "/"); print arr[n],$9,$10,$6}}'
    echo
    sleep 1
done
