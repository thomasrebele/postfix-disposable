#!/bin/bash

if [ "$1" == "" ]; then
	echo "usage: <user@server>"
	exit 1
fi

while inotifywait -q -e modify postfix_disposable.py disposable_config.py >/dev/null; do
	rsync -av postfix_disposable.py disposable_config.py "$1:/etc/postfix/"
done

