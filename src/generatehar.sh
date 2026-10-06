#!/usr/bin/env bash
## first argument is input file
## second argument is output folder

if [ -z "$1" ]
then
    echo "Missing input, provide a text-file with hosts to resolve"
    exit
else
    if [ -f "$1" ]; then
        echo "Using '$1' as input data"
    else
        echo "Input file '$1' does not exist!"
        exit 1
    fi
fi

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
elif hash chromium 2>/dev/null; then
    browser=chromium
    echo "Found chromium-browser on path!"
elif hash chrome-browser 2>/dev/null; then
    browser=chrome-browser
    echo "Found chrome-browser on path!"
elif hash google-chrome 2>/dev/null; then
    browser=google-chrome
    echo "Found google-chrome on path!"
elif hash google-chrome-stable 2>/dev/null; then
    browser=google-chrome-stable
    echo "Found chrome-browser-stable on path!"
elif command -v /Applications/Chromium.app/Contents/MacOS/Chromium 2>/dev/null; then
    browser=/Applications/Chromium.app/Contents/MacOS/Chromium
    echo "Found OSX and Chromium browser"
elif command -v /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome 2>/dev/null; then
    browser=/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
    echo "Found OSX and Chrome browser"
else
    echo "No compatible browser found!"
    exit 1
fi

# ensure that we have the folder
mkdir -p $folder

flags="--remote-debugging-port=9222 --no-sandbox --headless --content --disable-gpu --download-whole-document --deterministic-fetch --disk-cache-size=0 --net-log-capture-mode=IncludeCookiesAndCredentials"

# start chrome if not running
if ! (pgrep -f ".*$flags" > /dev/null) ; then
    echo "Starting headless browser ($browser)"

    ## --no-sandbox required for linux and root
    startcmd="${browser} $flags"
    echo "Starting '$startcmd'"
    $startcmd 2> /chrome_errors.log &

    ## sometimes we have had issues here, sleeping lets Chrome properly boot up
    sleep 2
else
    echo "Did not start headless browser, trying to use existing"
fi
    
# Give each page 30 sec to load in total, and wait 4 sec after load, retry once
echo "Starting chrome-har-capturer"
cat $1 | xargs chrome-har-capturer --retry 1 --grace 4000 --timeout 30000 -o $folder/last_run.har > har_errors.log
## FIX: Make sure the python script reads from all har files.
#parallel --xargs -s 300 chrome-har-capturer --retry 1 --grace 4000 --timeout 30000 -o $folder/last_run.har {} :::: $1 > har_errors.log
#xargs chrome-har-capturer --retry 3 --grace 4000 --timeout 20000 -o $folder/last_run.har < $1
#xargs chrome-har-capturer -o $folder/last_run.har < $1

# HACK 
# sleep a bit so the disk might stabilize (had issues on hdds)
sleep .01
    
echo "Cleaning Chrome process (pid $$)"
pkill -P $$
echo "Chrome headless and scripts cleaned up"

