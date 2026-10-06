#!/usr/bin/env zsh

# run from the script's folder, regardless of where we are called from
cd "$(dirname "$0")" || exit 1

# set folder
rfcs=rfcs

# set SKIP_SYNC=1 to reuse an existing copy
if [ -z "${SKIP_SYNC:-}" ]; then
    echo "rsyncing text versions of rfcs (and int stds)"
    rsync -avz --delete ftp.rfc-editor.org::rfcs-text-only ${rfcs} || exit 1
fi

## logic below
# 1) find all 'RFC XXXX,' references in the std/bcp index files
# 2) cat 'rfc' + number + '.txt'
# 3) count lines / words / bytes

# highest number matching the (extended) regex $2 in file $1
function get_max_index {
    grep -oE "$2" $1 | grep -oE "[0-9]+" | sort -n | tail -n 1
}

# rfc numbers referenced as 'RFC 1234,' in an std/bcp index file
function get_rfc_list {
    grep -oE "RFC [0-9]+," $1 | grep -oE "[0-9]+" | sort -nu
}

# existing files for the rfcs in an index file
function get_rfc_filenames {
    get_rfc_list $1 | while read -r n; do
        f="${rfcs}/rfc${n}.txt"
        if [ -f "$f" ]; then echo "$f"; else echo "warning: missing $f" >&2; fi
    done
}

# prints "lines words" for non-empty lines of the files on stdin
function count_lines_words {
    xargs cat | grep -v '^[[:space:]]*$' | wc -lw | awk '{ print $1, $2 }'
}

# prints size in MiB (rounded) of the files on stdin
function count_mib {
    xargs cat | wc -c | awk '{ printf "%d", $1 / 1048576 + 0.5 }'
}

## rfcs, just cat and count
rfc_files() { ls ${rfcs}/rfc[0-9]*.txt; }
read rfc_lines rfc_words <<< "$(rfc_files | count_lines_words)"
rfc_size=$(rfc_files | count_mib)
rfc_nr=$(rfc_files | wc -l | tr -d ' ')
rfc_max=$(get_max_index ${rfcs}/rfc-index.txt '^[0-9]+ ')

## Use the std-index to figure out which rfcs to look in
idx=${rfcs}/std-index.txt
read intstd_lines intstd_words <<< "$(get_rfc_filenames $idx | count_lines_words)"
intstd_size=$(get_rfc_filenames $idx 2>/dev/null | count_mib)
intstd_nr=$(ls ${rfcs}/std/std[0-9]*.txt | wc -l | tr -d ' ')
intstd_max=$(get_max_index $idx '\[STD[0-9]+\]')

## Use the bcp-index to figure out which rfcs to look in
idx=${rfcs}/bcp-index.txt
read bcp_lines bcp_words <<< "$(get_rfc_filenames $idx | count_lines_words)"
bcp_size=$(get_rfc_filenames $idx 2>/dev/null | count_mib)
bcp_nr=$(ls ${rfcs}/bcp/bcp[0-9]*.txt | wc -l | tr -d ' ')
bcp_max=$(get_max_index $idx '\[BCP[0-9]+\]')

## prep the actual file used in latex table
file=rfc_word_lines.txt

echo "Writing results to '$file'"

{
    printf 'Total & \\num{%d} & \\num{%d} & \\num{%d} \\\\\n' $rfc_max $intstd_max $bcp_max
    printf 'Active & \\num{%d} & \\num{%d} & \\num{%d} \\\\\n' $rfc_nr $intstd_nr $bcp_nr
    printf 'Words & \\num{%d} & \\num{%d} & \\num{%d} \\\\\n' $rfc_words $intstd_words $bcp_words
    printf 'Lines & \\num{%d} & \\num{%d} & \\num{%d} \\\\\n' $rfc_lines $intstd_lines $bcp_lines
    # last row without trailing '\\'
    printf 'Size & \\SI{%d}{\\mega\\byte} & \\SI{%d}{\\mega\\byte} & \\SI{%d}{\\mega\\byte}\n' $rfc_size $intstd_size $bcp_size
} > $file
