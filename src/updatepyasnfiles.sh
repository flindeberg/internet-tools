#!/usr/bin/env bash
## Ensure that we have the files necessary for pyasn to run

if hash pyasn_util_download.py 2>/dev/null; then
    echo "Starting download scipt for routing info"
    pyasn_util_download.py --latest
    echo "Download done, convering file"
    pyasn_util_convert.py --single rib.*.bz2 pyasn.dat
    echo "Download AS-name json file"
    pyasn_util_asnames.py -o pyasn.json
else
    echo "Did not find pyasn tools. Did you install pyasn?"
    echo "pip3 install pyasn"
fi



