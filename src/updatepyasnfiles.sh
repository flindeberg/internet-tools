#!/usr/bin/env bash
## Ensure that we have the files necessary for pyasn to run


# check that we have pyasn
if hash pyasn_util_download.py 2>/dev/null; then
    echo "Starting download scipt for routing info (a rib-bz2 file)"
    ## both ipv4 and ipv6 routes (plain --latest is ipv4 only)
    pyasn_util_download.py --latestv46
    echo "Download done, convering file (rib-bz2 -> pyasn.dat)"
    pyasn_util_convert.py --single rib.*.bz2 pyasn.dat
    echo "Cleaning temporary rib-files (i.e. rib-bz2)"
    rm rib.*.bz2
    echo "Downloading AS-name json file (and saving to pyasn.json)"
    pyasn_util_asnames.py -o pyasn.json
else
    echo "Did not find pyasn tools. Did you install pyasn?"
    echo "  pip3 install pyasn  "
fi



