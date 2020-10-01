#!/usr/bin/env zsh
# prefer zsh

grep=grep # start with normal grep on path

# if we have ggrep (gnu-version), lets use it
if hash ggrep 2>/dev/null; then
	grep=ggrep
fi

# set folder
rfcs=rfcs

echo "rsyncing text versions of rfcs (and int stds)"
rsync -avz --delete ftp.rfc-editor.org::rfcs-text-only ${rfcs}


# get all rows conforming to 'email: "an address"' and get the domain and tld
# currently doesn't work well with dual "tlds", like co.uk, but they are so few they don't matter for now

echo "grepping for emails to top8.txt"
${grep} -i 'email:' ${rfcs}/*.txt | sed -E 's/[\"><]//' | sed -E 's/.*[.@]([A-Za-z0-9-]+\.[A-Za-z0-9]*$)/\1/' | ${grep} -vP 'rfc\d.*txt' | sort | uniq -c | sort -nr | head -n 8 | awk '{ print $1, "&", $2, "\\\\" }' > top8.txt

echo "grepping for top universities (assuming .edu)"
${grep} -i "email" ${rfcs}/*.txt | sed -E 's/["><]//' | sed -E 's/.*[.@]([A-Za-z0-9-]+\.[A-Za-z0-9]*$)/\1/' | ${grep} -vP "rfc\d.*txt" | ${grep} "\.edu" | sort | uniq -c | sort -rn | head -n 10 | awk '{ print $1, "&", $2, "\\\\" }' > top_uni.txt

# above is naive, lets be smarter

echo "grepping for fixed set of orgs"

file=top_orgs.txt

[ -f "$file" ] && rm "$file"

## Some organizations and different names for them, usus the standard grep format, i.e. "|" as "or"
for str in "Cisco" "Ericsson" "Huawei" "Juniper" "Microsoft\|msft\|\.ms" "Nokia" "IBM" "ATT" "MIT" "Google" "Yahoo" "IEEE" "Intel" "Qualcomm" "Apple" "ICANN" "Harvard" "Facebook\|fb.com" "Amazon\|aws" 
do
    res=$(${grep} -i "email" ${rfcs}/*.txt | sed -E 's/["><]//' | sed -E 's/.*[.@]([A-Za-z0-9-]+\.[A-Za-z0-9]*$)/\1/' | ${grep} -vP "rfc\d.*txt" | ${grep} -i $str | wc -l)
    cmp=$(echo $str | perl -pe 's/(.*?)(\\..*)/\1/')
    echo $res $cmp | awk '{ print $1, "&", $2, "\\\\" }' >> $file
done

# sort files
sort -nr $file -o $file

