#!/usr/bin/env bash

if [[ $EUID > 0 ]]; then
    exec sudo -E "$0" "$@"
fi

base=$(dirname $0)

APP="$base/build-root/install-vpp_debug-native/vpp/bin/vpp"
ARGS="-c $base/startup.conf"

USAGE="Usage: run.sh [ debug ]
       debug:	executes vpp under gdb"

if [ -z "$1" ]; then
    $APP $ARGS
elif [ "$1" == "debug" ]; then
     GDB_EX="-ex 'set print pretty on' "
     gdb $GDB_EX --args $APP $ARGS
else
	echo "$USAGE"
fi
