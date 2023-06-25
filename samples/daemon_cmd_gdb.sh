#!/bin/bash

# VSCode likes to add its own parameters to the GDB command, so just ignore
# them in this script, and use hardcoded values to start a gdbserver on the
# remote, then connect to it. This doesn't terminate until gdb detaches/exits
# or the debugged program exits.

IP="TARGET_IP"
GDB_PORT=61772

echo "gdb $GDB_PORT" | nc -N $IP 61171 &>/dev/null
nc -N $IP $GDB_PORT