#! /bin/sh
### BEGIN INIT INFO
# Provides:          ctrecorder
# Required-Start:    $remote_fs $syslog $time
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Startup script of ctrecorder
# Description:       Conntrack Recorder startup script
### END INIT INFO

# Author: Bartlomiej Korupczynski <software@klolik.org>
# Do NOT "set -e"

# PATH should only include /usr/* if it runs after the mountnfs.sh script
PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC="Conntrack events recorder"
NAME=ctrecorder
DAEMON=/usr/sbin/$NAME
DAEMON_ARGS=""
SCRIPTNAME=/etc/init.d/$NAME

TCP_PIDFILE="/var/run/$NAME.tcp.pid"
UDP_PIDFILE="/var/run/$NAME.udp.pid"

# Exit if the package is not installed
[ -x "$DAEMON" ] || exit 0

# Read configuration variable file if it is present
[ -r /etc/default/$NAME ] && . /etc/default/$NAME

# Load the VERBOSE setting and other rcS variables
. /lib/init/vars.sh

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.2-14) to ensure that this file is present
# and status_of_proc is working.
. /lib/lsb/init-functions


do_start() {
	if [ "$TCP_RUN" ]; then
		start-stop-daemon --start --quiet --pidfile $TCP_PIDFILE --exec $DAEMON -- -Cf $TCP_FILENAME -P $TCP_PIDFILE -p tcp $DAEMON_ARGS
		[ "$VERBOSE" != no ] && echo -n "$DAEMON:tcp"
	fi
	if [ "$UDP_RUN" ]; then
		start-stop-daemon --start --quiet --pidfile $UDP_PIDFILE --exec $DAEMON -- -Cf $UDP_FILENAME -P $UDP_PIDFILE -p udp $DAEMON_ARGS
		[ "$VERBOSE" != no ] && echo -n "$DAEMON:udp"
	fi
	[ "$VERBOSE" != no ] && echo "."
}

case "$1" in
  start)
	[ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC" "$NAME"
	do_start
	;;
  stop)
	[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
	start-stop-daemon --stop --quiet --pidfile $TCP_PIDFILE --oknodo --exec $DAEMON
	[ "$VERBOSE" != no ] && echo -n "$DAEMON:tcp"
	start-stop-daemon --stop --quiet --pidfile $UDP_PIDFILE --oknodo --exec $DAEMON
	[ "$VERBOSE" != no ] && echo -n "$DAEMON:udp"
	[ "$VERBOSE" != no ] && echo "."
	;;
  status)
	status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
	;;
  rotate)
	echo "TODO"
	;;
  logstats)
	echo "TODO"
	;;
  restart|force-reload)
	# dying process removes new pid files :(
	log_daemon_msg "Restarting $DESC" ${TCP_RUN:+"$NAME:tcp"} ${UDP_RUN:+"$NAME:udp"}

	PIDS=`pidof $NAME`
	mv "$TCP_PIDFILE" "$TCP_PIDFILE".old
	mv "$UDP_PIDFILE" "$UDP_PIDFILE".old

	do_start
	sleep 1
	mv "$TCP_PIDFILE" "$TCP_PIDFILE".new
	mv "$UDP_PIDFILE" "$UDP_PIDFILE".new

	mv "$TCP_PIDFILE".old "$TCP_PIDFILE"
	mv "$UDP_PIDFILE".old "$UDP_PIDFILE"
	kill $PIDS
	sleep 1
	mv "$TCP_PIDFILE".new "$TCP_PIDFILE"
	mv "$UDP_PIDFILE".new "$UDP_PIDFILE"
	;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|status|rotate|logstats|restart|force-reload}" >&2
	exit 3
	;;
esac

:
