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
    # $12=command, $9=%cpu, $10=%mem, $6=mem bytes
    top -bc -n 1 | awk '/\/(wazuh|osquery)/ {n = split($12, arr, "/"); print arr[n],$9,$10,$6}' | grep -v bash
    echo ""
    sleep 1
done