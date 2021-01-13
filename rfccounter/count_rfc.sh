#!/bin/env sh

# set folder
rfcs=rfcs

echo "rsyncing text versions of rfcs (and int stds)"
rsync -avz --delete ftp.rfc-editor.org::rfcs-text-only ${rfcs}

## rfcs, just cat and count
rfc_words=$(cat rfcs/rfc[0-9]*.txt | wc -w)
rfc_lines=$(cat rfcs/rfc[0-9]*.txt | wc -l)

## logic below
# 1) find all 'RFCXXXX' in index file
# 2) strip 'RFC' and leading zeroes in rfc-number
# 3) cat 'rfc' + number + '.txt'
# 4) count lines / words

function get_rfc_content {
    grep -o "RFC[0-9]*" $1 | sed 's/^RFC0*//' | xargs -I{} -n 1 cat "rfcs/rfc{}.txt"
}

## Use the std-index to figure out which rfcs to look in
idx=${rfcs}/std-index.txt
intstd_words=$(get_rfc_content $idx | wc -w)
intstd_lines=$(get_rfc_content $idx | wc -l)


## Use the bcp-index to figure out which rfcs to look in
idx=${rfcs}/bcp-index.txt
intstd_words=$(get_rfc_content $idx | wc -w)
intstd_lines=$(get_rfc_content $idx | wc -l)

# output to std out
printf "Words: RFC %'d, STD %'d, BCP %'d \n" $rfc_words $intstd_words $bcp_words
printf "Lines: RFC %'d, STD %'d, BCP %'d \n" $rfc_lines $intstd_lines $bcp_lines


## prep the actual file used in latex table
file=rfc_word_lines.txt

[ -f "$file" ] && rm "$file"

printf 'Words & \\num{%d} & \\num{%d} & \\num{%d} \\\\ \n' $rfc_words $intstd_words $bcp_words >> $file
printf 'Lines & \\num{%d} & \\num{%d} & \\num{%d} \\\\ \n' $rfc_lines $intstd_lines $bcp_lines >> $file

