#!/bin/bash

workdir=$(cd $(dirname $0); pwd)

if [ $# -eq 0 ]; then
    echo "usage: $0 args"
    exit 1
fi

for arg in "$@"; do
    if [ "$arg" = "--help" ]; then
        echo "show help menu"
        exit 0
    fi
done

case "$1" in
    start)
        echo "start"
        ;;
    stop)
        echo "stop"
        ;;
    restart)
        echo "restart"
        ;;
    *)
        echo "usage: $0 <start | stop | restart>"
esac