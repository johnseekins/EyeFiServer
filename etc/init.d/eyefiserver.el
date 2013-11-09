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
PIDFILE=/var/run/$NAME.pid
LOCKFILE=/var/lock/subsys/$NAME
SCRIPTNAME=/etc/init.d/$NAME
DAEMONARGS="--log=${LOGFILE} -d -p ${PIDFILE}"
DAEMON="${PSNAME} /opt/EyeFiServer/${NAME}.py"
FULLDAEMON="${DAEMON} ${DAEMONARGS}" 

#
#	Function that starts the daemon/service.
#
d_start() {
	echo -n "Starting $DESC"
	daemon --pidfile $PIDFILE $FULLDAEMON
        RETVAL=$?
        echo
        [ $RETVAL -eq 0 ] && touch $LOCKFILE
        return $RETVAL
}

#	Function that stops the daemon/service.
#
d_stop() {
	echo -n "Stopping $DESC"
	killproc -p $PIDFILE $DAEMON
        RETVAL=$?
        echo
        [ $RETVAL -eq 0 ] && rm -f $LOCKFILE
        return $RETVAL
}

case "$1" in
  start)
	d_start
	;;
  stop)
	d_stop
	;;
  restart)
	echo "Restarting $DESC"
	d_stop
	sleep 1
	d_start
	;;
  status)
        status -p $PIDFILE $DAEMON
        ;;
  *)
	echo "Usage: $SCRIPTNAME {start|stop|restart|status}" >&2
	exit 1
	;;
esac

exit 0
