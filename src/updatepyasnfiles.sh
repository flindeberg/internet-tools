#!/usr/bin/env bash
## Ensure that we have the files necessary for pyasn to run, i.e. current
## routing data (ipv4 and ipv6, ip -> asn) and the names of all AS:s
##
##   ./updatepyasnfiles.sh         -> pyasn_local.dat / .json (not in git),
##                                    used instead of the snapshot while newer
##   ./updatepyasnfiles.sh pyasn   -> pyasn.dat / .json, the snapshot in git
##
## Files end up next to this script, wherever it is called from.

set -euo pipefail

name="${1:-pyasn_local}"
cd "$(dirname "$0")"

# check that we have pyasn
if ! hash pyasn_util_download.py 2>/dev/null; then
    echo "Did not find pyasn tools. Did you install pyasn?"
    echo "  pip3 install pyasn  "
    exit 1
fi

## work in a temporary folder, so a failed or partial download never
## replaces files that work
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Starting download script for routing info (a rib-bz2 file, ~100 MB)"
## both ipv4 and ipv6 routes (plain --latest is ipv4 only)
(cd "$tmp" && pyasn_util_download.py --latestv46)
echo "Download done, converting file (rib-bz2 -> ${name}.dat)"
## in the temporary folder, so the header of the .dat names just the rib-file
## (asnutils reads the date of the data from it)
(cd "$tmp" && pyasn_util_convert.py --single rib.*.bz2 "${name}.dat")
echo "Downloading AS-name json file (and saving to ${name}.json)"
pyasn_util_asnames.py -o "$tmp/${name}.json"

mv "$tmp/${name}.dat" "$tmp/${name}.json" .
echo "Saved ${name}.dat and ${name}.json"
