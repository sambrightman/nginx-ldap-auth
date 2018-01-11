#!/usr/bin/env bash

DIR="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
CMD=${DIR}/nginx_ldap_auth_daemon.py

if [ ! -f "$CMD" ]; then
    echo "Could not find '$CMD'"
    exit 1
fi

PIDFILE=${DIR}/$(basename $CMD .py).pid
OUTFILE=${DIR}/$(basename $CMD .py).out
ERRFILE=${DIR}/$(basename $CMD .py).err

. /etc/init.d/functions

start() {
    echo -n "Starting ldap-auth-daemon: "

    pip install -e ${DIR}/python-ldap || failure

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
