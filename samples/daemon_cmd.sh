#!/bin/bash

# Helper script to send commands to the hookdaemon.
# Usage: ./daemon_cmd.sh IP_TO_DAEMON cmd --to execute
#
# The following will recompile the project on the daemon-side and re-inject
# the newly built library:
#   ./daemon_cmd.sh IP_TO_DAEMON hook
#
# Since `make` is absurdly slow on Windows on SMB shares due to missing
# page cache, we're better off running `make -n` on (this) Linux machine
# and sending only the resulting gcc commands to the daemon.

IP=$1
PORT=61171
shift
CMD="$@"

if [[ -z "$CMD" ]]; then
    CMD="hook"
fi

ret=0
if [[ $CMD == "hook" ]]; then
    ret=0
    curdir="."
    while IFS="\n" read tmpcmd; do
        if [[ $tmpcmd == "make["* ]] || [[ $tmpcmd == "make:"* ]]; then
            if [[ $tmpcmd =~ Entering[[:space:]]directory[[:space:]]\'([a-zA-Z0-9\\/-_]+)\' ]]; then
                curdir="${BASH_REMATCH[1]//$PWD/.}";
            elif [[ $tmpcmd =~ Leaving[[:space:]]directory[[:space:]]\'([a-zA-Z0-9\\/-_]+)\' ]]; then
                # assume we're going to the parent dir
                curdir=$(dirname ${BASH_REMATCH[1]//$PWD/.})
            fi
            :
        elif [[ $tmpcmd == "make "* ]]; then
            :
        elif [[ $tmpcmd != "" ]]; then
            cmd="${tmpcmd//$PWD/.}"
            if [[ $curdir != "." ]]; then
                cmd="cd $curdir && $cmd"
            fi
            echo $cmd
            nc_out=$(nc $IP $PORT <<< "${cmd//\"\"/\"\\\"}")
            if [[ $nc_out == "" ]]; then
                ret=0
            else
                IFS=
                echo $nc_out
                ret=1
                break
            fi
        fi
    done <<< "$(make -n)"
fi

if [[ "$ret" == "0" ]]; then
    nc $IP $PORT <<< "$CMD"
fi