#!/bin/sh
#
# list.sh [List per-interface instance details]
#
# List out each daemon PID, PID file, and if found socket.
#
cd /run

BASE="pesigitg/"

# Loop through daemon PID files
for PID_FILE in pesigitgd-*.pid; do
	PID=$(cat $PID_FILE)
	INT=$(basename $PID_FILE | awk '{ split($0, a, "-"); split(a[2], b, "."); print b[1] }')
	SOCK="status-$INT.sock"

	# Deeeetails
	echo -n "$PID (file: $PID_FILE"

	if [ -e "$BASE$SOCK" ]; then
		echo -n ", socket: $SOCK"
	fi

	echo ")"
done
