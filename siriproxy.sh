#!/bin/sh

#################################################################
# Modified script from methoddk to run SiriProxy in the background
# and auto-restart if it crashes
#
# This file should be kept in your ~/SiriProxy directory.
#
# Syntax:
# rvmsudo sh siriproxy.sh {start|keepalive|stop}
#
# start will run SiriProxy in the background
#
# keepalive checks once every 10 minutes to see if the server
# is up, and if not, restarts it, then confirms it is indeed 
# back up and running.
#
# keepalive can also be started in the background if you run with:
# rvmsudo sh siriproxy.sh keepalive 2>&1> ~/.siriproxy/keepalive.log &
#
# logs are stored in ~/.siriproxy (check keepalive.log for server
# status and debug.log & error.log for SiriProxy output)
#################################################################

START="rvmsudo siriproxy server 1>> ~/.siriproxy/debug.log 2>> ~/.siriproxy/error.log &"

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
