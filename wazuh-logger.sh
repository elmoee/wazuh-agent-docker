#!/bin/bash

logfile="/var/log/wazuh/stats.log"

if [ -e $logfile ]; then
   rm $logfile
fi

exec >$logfile

# Update top relative
top -b -d 1 -n 1 > /dev/null

# Start logging stats
trap "exit 0" SIGINT
while true 
do
    date +%s
    top -bc -n 1 | grep -E '[w]azuh|[o]squery' --line-buffered | grep -v logger --line-buffered | awk '{print $6,$9,$10,$12}'
    echo ""
    sleep 1
done