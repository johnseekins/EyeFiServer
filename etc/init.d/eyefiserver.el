#!/bin/sh
#
# $Id$
#
# eyefiserver	initscript for eyefiserver
#		This file should be placed in /etc/init.d.
#
# Original Author: Mattias Holmlund
#
# Updated By: Dan Sully, pike, John

#
### BEGIN INIT INFO
# Provides:          	eyefiserver
# Required-Start:    	$all
# Required-Stop:     	$all
# Should-Start:      	$all
# Should-Stop:       	$all
# Default-Start:     	2 3 4 5
# Default-Stop:      	0 1 6
# Short-Description:	Startup script for the EyeFiServer
# Description:		EyeFiServer sits on port 59278 waiting for soap requests from
#			an EyeFi SD card; see http://www.eye.fi
### END INIT INFO
#

. /etc/init.d/functions

DESC="EyeFiServer"
NAME=eyefiserver
LOGFILE=/var/log/$NAME.log
EYEFIUSER=apache
EYEFIGROUP=apache
PIDFILE=/var/run/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
PSNAME=python # name of the process
DAEMONARGS="--log=${LOGFILE} -d "
DAEMON="${PSNAME} /usr/local/bin/${NAME}"

#
#	Function that starts the daemon/service.
#
d_start() {
	daemonize --pidfile $PIDFILE $DAEMON $DAEMONARGS start
}


#	Function that stops the daemon/service.
#
d_stop() {
	daemonize --pidfile $PIDFILE $DAEMON $DAEMONARGS stop
}

#
#	Function that sends a SIGHUP to the daemon/service.
#
#d_reload() {
#	start-stop-daemon --stop --quiet --pidfile $PIDFILE \
#		--name $PSNAME --signal 1
#}

case "$1" in
  start)
	echo -n "Starting $DESC"
	d_start
	echo "."
	;;
  stop)
	echo -n "Stopping $DESC"
	d_stop
	echo "."
	;;
  reload|force-reload)
	echo -n "Reloading $DESC"
	d_reload
	echo "."
	;;
  restart)
	echo -n "Restarting $NAME"
	d_stop
	sleep 1
	d_start
	echo "."
	;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
	exit 1
	;;
esac

exit 0
