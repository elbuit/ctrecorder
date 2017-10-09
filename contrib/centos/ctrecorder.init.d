#!/bin/bash
#
# ctrecorder      This shell script takes care of starting and stopping ctrecorder
#
# chkconfig: - 80 20
#
### BEGIN INIT INFO
# Provides: ctrecorder
# Required-Start: $network $syslog
# Required-Stop: $network $syslog
# Default-Start:
# Default-Stop:
# Description: Ctrecorder initscript
# Short-Description: start and stop ctrecorder
### END INIT INFO

# Source function library.
. /etc/rc.d/init.d/functions

start () {
    [ -d /var/log/ctrecorder ] || mkdir /var/log/ctrecorder
    echo -n $"Starting ctrecorder: "
    daemon ctrecorder -Cf /var/log/ctrecorder/tcp-%Y%m%d-%H%M%S.ct -t 1440
    RETVAL=$?
    echo
    [ $RETVAL -eq 0 ] && pidof ctrecorder > /var/run/ctrecorder.pid
    return $RETVAL
}

stop () {
    echo -n $"Shutting down ctrecorder: "
    killproc ctrecorder
    rm -f $pidf
}

restart () {
    stop
    start
}

status () {
    status ctrecorder
}

case "$1" in
    start)
        start
        RETVAL=$?
        ;;
    stop)
        stop
        RETVAL=$?
        ;;
    restart)
	restart
        RETVAL=$?
        ;;
    status)
        status
        RETVAL=$?
        ;;
    *)
        echo $"Usage: $0 {start|stop|restart|status}"
        RETVAL=2
        ;;
esac

exit $RETVAL
