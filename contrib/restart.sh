#!/bin/sh
# fairly safe method of restarting ctrecorder

INTERVAL=360
NFNL_BUF=2048
INT_BUF=3000

#set -x

OLD=`pidof ctrecorder`
echo "Old PID: $OLD"

ctrecorder -Cf /var/log/ulog/tcp-%Y%m%d-%H%M%S.ct -t $INTERVAL -b $NFNL_BUF -B $INT_BUF

sleep 1
NEW=`pidof -o $OLD ctrecorder`
echo "New PID: $NEW"

[ -z "$NEW" ] && echo "Startup failed" && exit 1
[ -z "$OLD" ] && exit 0

kill "$OLD"

