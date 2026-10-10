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

## prefer chromium over chrome, obviously..
## only accept browsers that actually run, e.g. Ubuntu's chromium-browser can be a snap stub
browser=""
for candidate in chromium-browser chromium chrome-browser google-chrome google-chrome-stable \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
    if command -v "$candidate" > /dev/null 2>&1 && "$candidate" --version > /dev/null 2>&1; then
        browser="$candidate"
        echo "Found working browser '$browser'"
        break
    fi
done

if [ -z "$browser" ]; then
    echo "No compatible browser found!"
    exit 1
fi

# ensure that we have the folder
mkdir -p $folder

## isolated profile dir, otherwise Chrome's single-instance behaviour forwards
## these flags to an already-running (non-headless) Chrome instance and silently
## ignores --headless / --remote-debugging-port
flags="--remote-debugging-port=9222 --no-sandbox --headless --content --disable-gpu --download-whole-document --deterministic-fetch --disk-cache-size=0 --net-log-capture-mode=IncludeCookiesAndCredentials --user-data-dir=$folder/chrome-profile"
read -ra flagsarr <<< "$flags"

# start chrome if not running
if ! (pgrep -f ".*$flags" > /dev/null) ; then
    echo "Starting headless browser ($browser)"

    ## --no-sandbox required for linux and root
    ## use an array so browser paths containing spaces (e.g. macOS "Google Chrome.app") work
    echo "Starting '$browser' with flags '$flags'"
    "$browser" "${flagsarr[@]}" 2> "$folder/chrome_errors.log" &

    ## wait (max 20 s) for the debugging port, instead of hoping a fixed sleep is enough
    for _ in $(seq 40); do
        curl -s http://127.0.0.1:9222/json/version > /dev/null && break
        sleep 0.5
    done
    if ! curl -s http://127.0.0.1:9222/json/version > /dev/null; then
        echo "Headless browser did not start, see $folder/chrome_errors.log:"
        tail -n 20 "$folder/chrome_errors.log"
        exit 1
    fi
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

