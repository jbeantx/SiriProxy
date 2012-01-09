#!/bin/sh

#################################################################
# Put this in your ~/SiriProxy directory &
# Run with rvmsudo sh siriproxy.sh {start|keepalive|stop}
#
# start will run SiriProxy in the background
#
# keepalive checks once every 10 minutes to see if the server
# is up, and if not, restarts it, then confirms it is indeed 
# back up and running.
#
# keep alive *should* go to background as well if you run as
# rvmsudo sh siriproxy.sh keepalive 2>&1> ~/.siriproxy/keepalive.log &
#
# if you need stop explained, get away from the keyboard and take
# cover under an interior doorway, quick.
#
# all logs are in ~/SiriProxy, check keepalive.log for server status
# and proxy.out & proxy.err for SiriProxy output.
#################################################################

START="rvmsudo siriproxy server 1> ~/.siriproxy/debug.log 2> ~/.siriproxy/error.log &"

case $1 in
start)
$START
exit 0
;;
stop)
echo "Stopping..."
sudo killall -w -g sleep > /dev/null
sudo killall siriproxy > /dev/null
echo "Done."
exit 0
;;
# all code by methoddk
keepalive)
while true; do
	if ps ax | grep -v grep | grep "$HOME/.rvm/gems/ruby-1.9.3-p0@SiriProxy/bin/" > /dev/null
	then
		echo $(date) "SiriProxy is running!"
	else
		echo $(date) "SiriProxy is not running. Restarting..."
		${START}
		sleep 5
		if ps ax | grep -v grep | grep "$HOME/.rvm/gems/ruby-1.9.3-p0@SiriProxy/bin/" > /dev/null
			then
				echo $(date) "SiriProxy is running!"
			else
				echo $(date) "Something is wrong."
		fi
	fi
	sleep 600
done
;;
*)
echo "Usage: rvmsudo sh $0 {start|keepalive|stop}"
exit 0
;;
esac