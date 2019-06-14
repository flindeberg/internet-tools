#!/bin/bash
## first argument is input file
## second argument is output folder

if [ -z "$2" ]
then
    folder=`echo $(date +'hars-%F-%T') | sed 's/:/_/g'`
else
    folder="$2"
fi

if hash chromium-browser 2>/dev/null; then
    browser=chromium-browser
    ## prefer chromium over chrome, obviously..
    echo "Found chromium-browser on path!"
elif hash chrome-browser 2>/dev/null; then
    browser=chrome-browser
    echo "Found chrome-browser on path!"
elif hash /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome 2>/dev/null; then
    browser=/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
    echo "Found OSX and Chrome browser"
fi

# ensure that we have the folder
mkdir -p $folder

# start chrome if not running
if ! (pgrep -x ".*Chrome" > /dev/null) ; then
    echo "Starting Chrome headless"
    ## TODO, adapt for non-OSX OSes
    ${browser} --headless --content --disk-cache-dir=/dev/null --disable-gpu --download-whole-document --deterministic-fetch --net-log-capture-mode IncludeCookiesAndCredentials &> /dev/null &

    ## sometimes we have had issues here, sleeping lets Chrome properly boot up
    sleep 2
fi
    
# Give each page 20 sec to load in total, and wait 3 sec after load
xargs chrome-har-capturer -g 3000 -u 20000 -c -f -o $folder/run.har < $1
sleep .01
    
echo "Cleaning Chrome process (pid $$)"
pkill -P $$
echo "Chrome headless and scripts cleaned up"

