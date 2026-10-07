#!/usr/bin/env zsh
# prefer zsh

# run from the script's folder, regardless of where we are called from
cd "$(dirname "$0")" || exit 1

# byte-wise text handling, so GNU grep does not treat RFCs with non-UTF-8 bytes as binary
export LC_ALL=C

# set folder
rfcs=rfcs

# number of rows in the domain tables
top=8

# set SKIP_SYNC=1 to reuse an existing copy
if [ -z "${SKIP_SYNC:-}" ]; then
    echo "rsyncing text versions of rfcs (and int stds)"
    rsync -avz --delete ftp.rfc-editor.org::rfcs-text-only ${rfcs} || exit 1
fi

# get the domain of every address on an 'email:' line, one per line, lowercased
# keeps three labels for two-letter ccTLDs with a generic second level, e.g. ox.ac.uk, bt.co.uk
function domains {
    ls ${rfcs}/rfc[0-9]*.txt | xargs grep -ahi 'e-\{0,1\}mail:' \
        | grep -oE '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}' \
        | sed 's/.*@//' | tr 'A-Z' 'a-z' \
        | awk -F. '{
            n = NF
            if (n >= 3 && length($n) == 2 && $(n-1) ~ /^(co|ac|com|net|org|edu|gov|ne|or)$/)
                print $(n-2) "." $(n-1) "." $n
            else
                print $(n-1) "." $n
        }'
}

# "count domain" -> "count & domain \\"
function to_latex {
    awk '{ print $1, "&", $2, "\\\\" }'
}

# merge two latex tables side by side, padding the shorter one
function two_col {
    awk 'NR == FNR { a[FNR] = $0; na = FNR; next }
         { b[FNR] = $0; nb = FNR }
         END {
             n = na > nb ? na : nb
             for (i = 1; i <= n; i++) {
                 l = (i in a) ? a[i] : "& \\\\"
                 r = (i in b) ? b[i] : "& \\\\"
                 sub(/ *\\\\$/, " \\&", l)
                 print l, r
             }
         }' $1 $2
}

tmp=$(mktemp -d "${TMPDIR:-/tmp}/parse_rfc.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

echo "extracting email domains"
domains | sort | uniq -c | sort -nr > $tmp/domains

echo "top domains to top8.txt"
head -n $top $tmp/domains | to_latex > top8.txt

echo "top universities (assuming .edu) to top_uni.txt"
grep '\.edu$' $tmp/domains | head -n $top | to_latex > top_uni.txt

echo "fixed set of orgs to top_orgs.txt"

## Organizations as "Name:regex", the regex is matched (extended, anchored) against the domain
orgs=(
    "Cisco:cisco"
    "Ericsson:ericsson"
    "Huawei:huawei"
    "Juniper:juniper"
    "Microsoft:microsoft|msft"
    "Nokia:nokia|nokia-bell-labs"
    "IBM:ibm"
    "ATT:att"
    "MIT:mit"
    "Google:google"
    "Yahoo:yahoo|yahoo-inc"
    "IEEE:ieee"
    "Intel:intel"
    "Qualcomm:qualcomm"
    "Apple:apple"
    "ICANN:icann"
    "Harvard:harvard"
    "Facebook:facebook|fb"
    "Amazon:amazon|aws"
)

for org in "${orgs[@]}"; do
    name=${org%%:*}
    re=${org#*:}
    awk -v re="^($re)\\\\." -v name="$name" '$2 ~ re { s += $1 } END { print s + 0, name }' $tmp/domains
done | sort -nr | to_latex > top_orgs.txt

# split the orgs in two halves and put them side by side
half=$(( ($(wc -l < top_orgs.txt) + 1) / 2 ))
head -n $half top_orgs.txt > $tmp/left
tail -n +$((half + 1)) top_orgs.txt > $tmp/right
two_col $tmp/left $tmp/right > top_orgs_2col.txt

echo "merged to two col format for top orgs"

two_col top8.txt top_uni.txt > top_domains_2col.txt

echo "merged to two col format for domains"
