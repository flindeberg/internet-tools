#!/bin/bash

read -p "You will need GNU Parallel, Python3 (with pyasn), and a local recursive dns server use this script (Y/*): " understood && [[ $understood == [yY] || $understood == [yY][eE][sS] ]] || exit 1

if [ ! -f "zonedata_ch_script.key" ]; then
    cat <<EOT >> zonedata_ch_script.key
# filename zonedata.key
key tsig-zonedata-ch-public-21-01 {
    algorithm hmac-sha512;
    secret "stZwEGApYumtXkh73qMLPqfbIDozWKZLkqRvcjKSpRnsor6A6MxixRL6C2HeSVBQNfMW4wer+qjS0ZSfiWiJ3Q==";
};
EOT
fi

zonefiles=(*.zone.txt)

ns_all=ns_zones_all.txt
ns_uniq=ns_zones.txt
ip_all=ip_all.txt
ip_uniq=ip_uniq.txt

## Check for zone-files and use them
if compgen -G "*.zone.txt" > /dev/null; then
    echo "Found some zone-file(s), using them"
    cat *.zone.txt | sed 's/ /\t/g' | grep -E $'\tNS\t' | tr -s $'\t' | cut -d $'\t' -s -f5 | grep -v "^$" > ${ns_all}
else
    echo "Did not find any zone-file on format 'tld.zone.txt', defaulting to se, ee, nu, and ch."
    echo "Doing extensive dig to get ee., ch., se., and nu. zones."
    echo "(this script does not save them to disk)"
    (dig @zonedata.iis.se se AXFR ; dig @zonedata.iis.se nu AXFR ; dig @zone.internet.ee ee. AXFR ; dig -k zonedata_ch_script.key @zonedata.switch.ch AXFR ch. ) | sed 's/ /\t/g' | grep -E $'\tNS\t' | tr -s $'\t' | cut -d $'\t' -s -f5 | grep -v "^$" > ${ns_all}
fi

## Sort it
echo "Saving all names and unique names, all in '${ns_all}' and uniq in '${ns_uniq}'."
cat ${ns_all} | sort -u > ${ns_uniq}

## check if we have a local resolver
echo "Trying local resolver..."
dig +short +time=1 +tries=1 @::1 ns . > /dev/null
if [ "$?" -ne 0 ];
then
    echo "Did not find local DNS resolver, will use 8.8.8.8 which is limited to 1500 queries per second."
    read -p "This will take an exessive amount of time. Are you sure? (Y/*): " understood && [[ $understood == [yY] || $understood == [yY][eE][sS] ]] || (echo "Quitting..." && exit 1)
    ## Google throttles less aggressively than cloudflare..
    ## Google limits to 1500 qps after a while, cloudflare seems to just drop all your queries
    serv="@8.8.8.8"
else
    echo "Found local server, using it"
    serv="@::1"
fi

## Resolve them
## TODO Also resolve IPv6
echo "Resolving NS-records..... (might take while, it is $(wc -l ${ns_uniq}) hostnames to resolve)"
parallel --jobs 250 --xargs -s 1000 dig +short $serv {} :::: ${ns_uniq} > ${ip_all}

# sorted and uniq
cat ${ip_all} | sort -u > ${ip_uniq}

if [ ! -f "aslookup.py" ]; then
    echo "> 'aslookup.py' not found, writing default version."
    ## I found no good bash / commandline tool to quickly look up
    ## large amounts of IPs, therefore we use the splendid pyasn and
    ## python.
    cat <<EOT >> aslookup.py
#!/bin/python3
import pyasn
import ipaddress
import fileinput

# Initialize module and load IP to ASN database
# the sample database can be downloaded or built - see below
asndb = pyasn.pyasn('pyasn.dat', as_names_file="pyasn.json")

for line in fileinput.input():
    try:
        ipaddress.ip_address(line.strip())
        ## works, lets go one
        res=asndb.lookup(line.strip())
        name=asndb.get_as_name(res[0])
        # format: ASN \t NAME_OF_AS \t PREFIXES_ANNOUNCED_BY_AS
        print("{}\t{}\t{}".format(res[0], name, res[1]))
    except ValueError:
        # ignore as well
        pass
    except ipaddress.AddressValueError:
        # ignore, we live in denial
        pass
EOT
fi

## Lets create a venv
echo "Creating and entering a venv for python"
python3 -m venv .
source bin/activate
pip3 install pyasn

## This requires pyasn
if [ ! -f "pyasn.dat" ]; then
    echo "Downloading BGP-dump data..."
    rm -f rib.*.bz2
    pyasn_util_download.py --latestv46
    pyasn_util_convert.py --single rib.*.bz2 pyasn.dat
fi

if [ ! -f "pyasn.json" ]; then
    echo "Downloading names for AS..."
    pyasn_util_asnames.py -o pyasn.json
fi

## Do some things with the as(n) data
asn=$(cat ${ip_uniq} | python3 aslookup.py | cut -f 1 | sort -u | wc -l)
ascountries=$(cat ${ip_uniq} | python3 aslookup.py | cut -f 2 | sort | rev | cut -d',' -f 1 | rev | sort -u | wc -l)

echo "The NS-records point to ${asn} different ASNs registred in ${ascountries} different countries"

echo "Top ten countries (registred location of AS announcing prefix containing IP of authoritative nameserver)"
cat ${ip_all} | python3 aslookup.py | cut -f 2 | sort | rev | cut -d',' -f 1 | rev | sort | uniq -c | sort -nr | head -n 10

echo "Top ten AS for nameservers in '${zonefiles}'."
cat ${ip_all} | python3 aslookup.py | cut -f 1,2 | sort | uniq -c | sort -nr | head -n 10

echo "Redoing with all IPs, should be quick due to cache"
parallel --jobs 250 --xargs -s 1000 dig +short $serv {} :::: ${ns_all} > ${ip_all}

echo "Top ten countries (registred location of AS announcing prefix containing IP of authoritative nameserver)"
cat ${ip_all} | python3 aslookup.py | cut -f 2 | sort | rev | cut -d',' -f 1 | rev | sort | uniq -c | sort -nr | head -n 10

echo "Top ten AS for nameservers in '${zonefiles}'."
cat ${ip_all} | python3 aslookup.py | cut -f 1,2 | sort | uniq -c | sort -nr | head -n 10

## echo zone / asns / countries / top 3
topthree=$(cat ${ip_all} | python3 aslookup.py | cut -f 2 | sort | rev | cut -d',' -f 1 | rev | sort | uniq -c | sort -nr | head -n 5 | tr -s $'\t' ' ' | cut -d' ' -f 3 | tr '\n' ', ' | sed 's/,$/\n/g')

botthree=$(cat ${ip_all} | python3 aslookup.py | cut -f 2 | sort | rev | cut -d',' -f 1 | rev | sort | uniq -c | sort -n | head -n 5 | tr -s $'\t' ' ' | cut -d' ' -f 3 | tr '\n' ', ' | sed 's/,$/\n/g')

echo "LaTeX-table-line:"
ips=$(cat $ip_uniq | wc -l)
echo "${zonefiles} & ${ips} & ${asn} & ${ascountries} & ${topthree} \\\\"
