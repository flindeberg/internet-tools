#!/usr/bin/env zsh

# set folder
rfcs=rfcs

echo "rsyncing text versions of rfcs (and int stds)"
rsync -avz --delete ftp.rfc-editor.org::rfcs-text-only ${rfcs}


## logic below
# 1) find all 'RFCXXXX' in index file
# 2) strip 'RFC' and leading zeroes in rfc-number
# 3) cat 'rfc' + number + '.txt'
# 4) count lines / words

function get_max_index {
    grep -o "^[0-9]*" $1 | sort | tail -n 1 | grep -o "[1-9].*$"
}

function get_rfc_list {
    grep -o "RFC[0-9]*" $1 | sed 's/^RFC0*//'
}

function get_rfc_filenames {
    get_rfc_list $1 | xargs -I{} -n 1 echo "${rfcs}/rfc{}.txt"
}

function get_rfc_content {
    get_rfc_list $1 | xargs -I{} -n 1 cat "${rfcs}/rfc{}.txt" | grep -v ^$
}

## rfcs, just cat and count
rfc_words=$(cat rfcs/rfc[0-9]*.txt | grep -v ^$ | wc -w)
rfc_lines=$(cat rfcs/rfc[0-9]*.txt | grep -v ^$ | wc -l)

rfc_max=$(get_max_index rfcs/rfc-index.txt)
rfc_nr=$(ls rfcs/rfc[0-9]*.txt | wc -l)

rfc_size=$(du -cksh rfcs/rfc[0-9]*.txt | tail -n1 | cut -f1)

## Use the std-index to figure out which rfcs to look in
idx=${rfcs}/std-index.txt
intstd_words=$(get_rfc_content $idx | wc -w)
intstd_lines=$(get_rfc_content $idx | wc -l)

intstd_max=$(get_max_index rfcs/std-index.txt)
intstd_nr=$(ls rfcs/std/std[0-9]*.txt | wc -l)

intstd_size=$(get_rfc_filenames $idx | xargs du -cksh | tail -n1 | cut -f1)

## Use the bcp-index to figure out which rfcs to look in
idx=${rfcs}/bcp-index.txt
bcp_words=$(get_rfc_content $idx | wc -w)
bcp_lines=$(get_rfc_content $idx | wc -l)

bcp_max=$(get_max_index rfcs/bcp-index.txt)
bcp_nr=$(ls rfcs/bcp/bcp[0-9]*.txt | wc -l)

bcp_size=$(get_rfc_filenames $idx | xargs du -cksh | tail -n1 | cut -f1)

## prep the actual file used in latex table
file=rfc_word_lines.txt

[ -f "$file" ] && rm "$file"

printf 'Total & \\num{%d} & \\num{%d} & \\num{%d} \\\\ \n' $rfc_max $intstd_max $bcp_max >> $file
printf 'Active & \\num{%d} & \\num{%d} & \\num{%d} \\\\ \n' $rfc_nr $intstd_nr $bcp_nr >> $file
printf 'Words & \\num{%d} & \\num{%d} & \\num{%d} \\\\ \n' $rfc_words $intstd_words $bcp_words >> $file
printf 'Lines & \\num{%d} & \\num{%d} & \\num{%d} \\\\ \n' $rfc_lines $intstd_lines $bcp_lines >> $file
printf 'Size & \\SI{%d}{\\mega\\byte} & \\SI{%d}{\\mega\\byte} & \\SI{%d}{\\mega\\byte} \\\\ \n' ${rfc_size%?} ${intstd_size%?} ${bcp_size%?} >> $file

# #HACK remove the last "\\" and add newline again
truncate -s-4 $file
echo "" >> $file


