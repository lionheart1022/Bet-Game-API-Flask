#!/bin/bash
exec gunicorn "$@" \
	--access-logfile /home/betgame/observer-access.log \
	--error-logfile /home/betgame/observer-errors.log \
	--workers 1 --worker-class eventlet \
	--bind localhost:8021 -m 007 \
	'observer:init_app("/home/betgame/observer.log")'
