#!/bin/sh

CMD=nginx_ldap_auth_daemon.py
if [ ! -f "$CMD" ]; then
    echo "Please run '$0' from the same directory where '$CMD' file resides"
    exit 1
fi

CMD=$PWD/$CMD
PIDFILE=$(basename $CMD .py).pid
OUTFILE=$(basename $CMD .py).out
ERRFILE=$(basename $CMD .py).err

. /etc/init.d/functions

start() {
    echo -n "Starting ldap-auth-daemon: "
    if [ -s ${PIDFILE} ]; then
        PID=$(cat ${PIDFILE})
        if kill -0 ${PID} 2>/dev/null; then
            echo -n "Already running!" && warning
            echo
        else
            echo -n "Stale PID!" && failure
            echo
        fi
    else
        nohup ${CMD} >${OUTFILE} 2>${ERRFILE} &
        PID=$!
        sleep 1
        kill -0 ${PID} 2>/dev/null && success || failure
        echo
        kill -0 ${PID} 2>/dev/null && echo ${PID} > ${PIDFILE}
    fi
}

case $1 in
    "start")
        start
    ;;
    "stop")
        echo -n "Stopping ldap-auth-daemon: "
        killproc -p $PIDFILE $CMD
        echo
    ;;
    *)
        echo "Usage: $0 <start|stop>"
    ;;
esac
