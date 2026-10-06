#!/usr/bin/env python3
import ipaddress
from typing import Dict, List, NamedTuple
from dataclasses import dataclass
import pyasn
import pycountry
import json

import edgeutils

# clean company names
import cleanco

# match company names
import pandas as pd
from string_grouper import match_most_similar


## TLS adapted for workaround
import requests
from requests import adapters
import ssl
from urllib3 import poolmanager


class TLSAdapter(adapters.HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block=False):
        """Create and initialize the urllib3 PoolManager."""
        ctx = ssl.create_default_context()
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        self.poolmanager = poolmanager.PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_version=ssl.PROTOCOL_TLS,
            ssl_context=ctx,
        )


@dataclass
class AS:
    """
    Class to represent prettyprintable autonomous systems

    Contain an inner collection of more meaningful AS (in a technical sense)
    """

    ### Class to represent-AS entities
    # self.name: str
    # self.asn: int
    # self.cc: str
    # self.exampleIp: str

    def __init__(
        self, name: str, asn: int, cc: str, exampleIp: str, company: str = None
    ):
        self.name = name
        self.asn = asn
        self.cc = cc
        self.exampleIp = exampleIp
        self.company = company
        self.presumtivecompany = self.company

    @classmethod
    def CreateFromDict(cls, ip, d):
        ## just create and return
        ## d is assumed to come from cymruwhois
        return AS(d.owner, d.asn, d.cc, ip)

    @classmethod
    def CreateFromPyasnStr(cls, ip: str, asn: int, s: str):
        ## create and return basically.
        if s is not None:
            country = pycountry.countries.get(alpha_2=s[-2:])
            if country is not None:
                country = s[-2:]
                # lets remote the last four, i.e. ", XX"
                s = s[:-4]
        else:
            country = ""

        return AS(s, asn, country, ip)

    def GetPrettyName(self) -> str:
        ## Gets a pretty representation of the AS
        ## for now "AS full name (ASN)", i.g. "Google LLC (1234)"
        if self.cc == "" or self.cc == None:
            return "{:}\n({:})".format(self.name, self.asn)
        ## return the country code as well if we have it
        return "{:}\n({:}, {:})".format(self.name, self.asn, self.cc)

    def __str__(self):
        return self.GetPrettyName()

    def __repr__(self):
        return self.__str__()


## Type aliases
AsList = List[AS]
EdgeList = List[edgeutils.EdgeTuple]
AsDict = Dict[int, AS]
IpAsDict = Dict[ipaddress._BaseAddress, AS]


class AsInfo(NamedTuple):
    # IP to AS mappings
    ipas: IpAsDict = dict()
    # ASN to AS mapping
    asas: AsDict = dict()  # Type AsDict


@dataclass
class ASFind:
    def __init__(
        self,
        asns: List[int],
        start: ipaddress._BaseAddress,
        end: ipaddress._BaseAddress,
    ):
        """
        Initiate a new ASFind object, based on ASNs (ints), and an address range
        """
        super().__init__()

        self._CIDRs = list(ipaddress.summarize_address_range(start, end))
        self._ASNs = asns

    @property
    def CIDRs(self):
        """Returns CIDRs represented by this object"""
        return self._CIDRs

    @property
    def ASNs(self):
        return self._ASNs

    def contains(self, ip: ipaddress._BaseAddress) -> List[int]:
        """
        Checks if the IP is contained in this ASFind object
        """
        # check if we have a CIDR containing the ip
        # if we do, return the first asn
        for cidr in self.CIDRs:
            if ip in cidr:
                ## lets just return all of the ASNs instead of cherry picking here
                return self.ASNs

        ## no match, lets return None
        return None

    def addIPrange(self, start: ipaddress._BaseAddress, end: ipaddress._BaseAddress):
        """Adds a new IP range to the CIDR collection"""
        self._CIDRs.extend(ipaddress.summarize_address_range(start, end))

    def addCIDRs(self, cidrs: List[ipaddress._BaseNetwork]):
        """Adds more CIDRs to the CIDR collection"""
        self._CIDRs.extend(cidrs)


class ASNLookup:
    """Class for looking up ASN data"""

    # currently based on pyasn, and has to be. They have the correct data
    __p = pyasn.pyasn("pyasn.dat", "pyasn.json")

    ## Url from which to do a curl for rdap data
    ## TODO Use rdap library, problematic currently since no rdap libs I've
    ## found have the "arin_originas0_originautnums" field (which is necessary)
    ## "arin_originas0_originautnums" is returned by arin
    __urlrdap = "https://rdap.arin.net/registry/ip/{:}"

    ## list with unnannounced AS which we have figured out
    __unannounced = list()

    def __init__(self):
        # load all names and pyas
        # self.p = pyasn.pyasn("pyasn.dat", "pyasn.json")

        # Our presumed object
        self._asinfo = AsInfo()

    def lookupmanystr(self, ips: List[str]) -> AsInfo:
        """Looks up AsInfo from a list of IP-addresses in string-type"""
        ipstyped = list()
        for ip in set(ips):  ## remove duplicates
            try:
                ## translate to typed
                ipc = ipaddress.IPv4Address(ip)
                ipstyped.append(ipc)
            except ValueError as ve:
                print("Issues with ip-address '{:}': {:}".format(ip, ve))

        return self.lookupmany(ipstyped)

    def lookupmany(self, ips: List[ipaddress.IPv4Address]) -> AsInfo:
        """Looks up AsInfo from a list of IP-addresses ipaddress.IPv4Address-type"""

        # Our presumed object
        # use instance variable for now
        asinfo = self._asinfo
        # asinfo = AsInfo()

        # go through ips and resolve  them
        for ip in ips:
            try:
                ## we know we have proper IPv4 address here

                ## IDEA:
                # 1) check if we have resolved that IP, if we have use it
                # 2) use pyasn (since pyasn is damn fast)
                # 3) check the local list of unnanounced networks
                # 4) some weird network, store but mark

                if ip in asinfo.ipas:
                    # We already have it, lets just continue
                    # print("IP-address {:} already in database ({:}).".format(ip.exploded, asinfo.ipas[ip].name))
                    continue

                # Sanity checks so we know what to do
                # Only check global and private ips
                if ip.is_global:
                    # we have a an IP which is global, i.e. should
                    # be routable
                    # tuple, 0 = asn, 1 = prefix
                    pyasntuple = ASNLookup.__p.lookup(ip.exploded)

                    if pyasntuple[0] == None and pyasntuple[1] == None:
                        ## We do not have this ASN / prefix

                        # check if we have it in our cache
                        res = None
                        for asn in ASNLookup.__unannounced:
                            res = asn.contains(ip)
                            ## break when we find a match
                            if res:
                                break

                        ## check for the hit again and use it
                        if res:
                            ## set the IP to point to first AS
                            ## Which is already populated
                            asinfo.ipas[ip] = asinfo.asas[res[0]]

                        else:
                            ## Lets create it
                            print(
                                "IP-address {:} is not announced, looking for it with RDAP towards ARIN.".format(
                                    ip.exploded
                                )
                            )
                            url = ASNLookup.__urlrdap.format(ip)

                            session = requests.session()
                            session.mount("https://", TLSAdapter())

                            with session.get(url) as rdap:
                                # with urllib.request.urlopen(url) as rdap:
                                data = json.loads(rdap.content.decode())
                                # data = json.loads(rdap.read().decode())
                                ## handle json
                                start = ipaddress.ip_address(data["startAddress"])  # ip
                                end = ipaddress.ip_address(data["endAddress"])  # ip

                                # ensure that we have the field and that we actually have data in it
                                if (
                                    "arin_originas0_originautnums" in data
                                    and len(data["arin_originas0_originautnums"]) > 0
                                ):
                                    asns = data["arin_originas0_originautnums"]  # list

                                    ## create and add to unannounced
                                    asf = ASFind(asns, start, end)
                                    ASNLookup.__unannounced.append(asf)

                                    ## update our internal mappings
                                    for a in asns:
                                        asn = AS.CreateFromPyasnStr(
                                            ip, a, ASNLookup.__p.get_as_name(asns[0])
                                        )
                                        asinfo.ipas[ip] = asn
                                        asinfo.asas[a] = asn
                                        print(
                                            "Added {:} ({:}) which covers {:} to {:}".format(
                                                asn.name,
                                                asn.asn,
                                                start.exploded,
                                                end.exploded,
                                            )
                                        )

                                else:
                                    # we do not have an ASN!
                                    # but we have a country, so lets go with that
                                    # lets create a negative number representing it
                                    if len(asinfo.asas) > 0:
                                        asns = [
                                            min(
                                                min(
                                                    [
                                                        i
                                                        for i in asinfo.asas
                                                        if isinstance(i, int)
                                                    ]
                                                )
                                                - 1,
                                                -1,
                                            )
                                        ]
                                    else:
                                        asns = [-1]

                                    ## create and add to unannounced even if we do not have it
                                    asf = ASFind(asns, start, end)
                                    ASNLookup.__unannounced.append(asf)

                                    if "country" in data:
                                        # lets also use name and country from whois
                                        name = data["name"]
                                        cc = data["country"]
                                    else:
                                        # assume bad country and we need to dig deeper for good name
                                        cc = "XX"
                                        name = data["name"]

                                    # EX: https://rdap.arin.net/registry/ip/150.222.244.8
                                    # we need entities -> (element in array) -> vcardarray -> [1] -> [1] -> [3] => Amazon Technologies Inc.
                                    # lets overwrite with whatever we find in vcard
                                    for entity in data["entities"]:
                                        # go through all entities
                                        # which match certain criteria
                                        if (
                                            "vcardArray" in entity
                                            and "roles" in entity
                                            and "abuse" not in entity["roles"]
                                        ):
                                            # we have a match, a vcardArray!
                                            # this is the magic position of the name in a vcardarray-record
                                            potential_name = entity["vcardArray"][1][1][
                                                3
                                            ]
                                            if not (
                                                "Role" in potential_name
                                                or "Abuse" in potential_name
                                                or "abuse" in potential_name
                                                or "role" in potential_name
                                            ):
                                                # We need to watch out here, might be unusable name
                                                name = potential_name
                                            break

                                    # if we have description that is even better, overwrite again
                                    if "remarks" in data:
                                        if len(data["remarks"]) > 0:
                                            if "description" in data["remarks"][0]:
                                                name = data["remarks"][0][
                                                    "description"
                                                ][0]

                                    if name == None:
                                        # We have no idea what is happening, failing for now
                                        # TODO decide if fail or not
                                        # raise ValueError("Could not find vcardArray in rdap-record! (undocumented case, we fail for now)")

                                        # Create a temporary name from CIDRS
                                        cidrs = [
                                            cidr.exploded
                                            for cidr in ipaddress.summarize_address_range(
                                                start, end
                                            )
                                        ]
                                        name = ", ".join(cidrs)

                                    ## update our internal mappings
                                    asn = AS(name, asns[0], cc, ip)
                                    # asn = AS.CreateFromPyasnStr(ip, asns[0], "{:}, {:}".format(name, cc))
                                    asinfo.ipas[ip] = asn
                                    asinfo.asas[asns[0]] = asn
                                    print(
                                        "Added {:} ({:}) which covers {:} to {:}".format(
                                            asn.name,
                                            asn.asn,
                                            start.exploded,
                                            end.exploded,
                                        )
                                    )

                    elif pyasntuple[0] == None or pyasntuple[1] == None:
                        ## We don't know this case, lets crash
                        raise ValueError(
                            "Get either ASN or prefix, undefined case, failing fast and early (might be possible bug, undocumented case)"
                        )

                    else:
                        ## pyasn got a good match, lets use pyasn fully
                        ## first, lets check if we have it already
                        if pyasntuple[0] in asinfo.asas:
                            # we have it, add ip and we are done
                            asinfo.ipas[ip] = asinfo.asas[pyasntuple[0]]  # ip -> as
                        else:
                            # We do not already have it, we need to create one
                            ## __p is the global pyasn instance, contents are cached and loaded to memory
                            name = ASNLookup.__p.get_as_name(pyasntuple[0])
                            asn = AS.CreateFromPyasnStr(
                                ip, pyasntuple[0], name
                            )  # really an as and not asn, but "as" is protected in Python

                            # lets create both dictionaries for now
                            asinfo.ipas[ip] = asn  # ip -> as
                            asinfo.asas[pyasntuple[0]] = asn  #

                elif ip.is_private:
                    ## local ip-address
                    cidr = ipaddress.ip_network(ip).supernet(new_prefix=24)

                    print(
                        "IP-address {:} is not public, adding as part of {:}.".format(
                            ip, cidr
                        )
                    )

                    name = "Private {:}".format(cidr)
                    if name not in asinfo.asas:
                        asn = AS.CreateFromPyasnStr(
                            ip, 0, name
                        )  # really an as and not asn, but "as" is protected in Python
                        asn.cc = "XX"
                        # lets create both dictionaries for now
                        asinfo.ipas[ip] = asn  # ip -> as
                        asinfo.asas[name] = asn  #
                    else:
                        ## for now, assume only one local network and reuse it
                        asinfo.ipas[ip] = asinfo.asas[name]  # ip -> as

                else:
                    ## TODO Should we do something here?
                    print(
                        "IP-address '{:}' is neither global nor local, skipping for now.".format(
                            ip
                        )
                    )

            except ValueError as ve:
                print("Issues with ip-address '{:}': {:}".format(ip, ve))

        # clean our dataset
        # HACK We only call clean outside for now
        # self.clean()

        # return what we created
        return asinfo

    def clean(self):
        """Cleans the instance AS and adds companies were applicble"""

        # HACK Use fixed list for companies for now
        # TODO Use a smart list of companies?
        masterlist = pd.Series(
            [
                "Bahnhof",
                "Tele2",
                "Comhem",
                "Bredbandsbolaget",
                "Telenor",
                "Netnod",
                "Amazon",
                "Google",
                "Microsoft",
                "Edgecast",
                "Telia",
                "TDC",
                "Cogent",
                "Level3",
                "Cloudflare",
                "Linode",
                "Yahoo",
                "Twitter",
                "Facebook",
                "AMS-IX",
                "LINX",
            ]
        )

        # start with iterating through the items and clean the names of potential companies
        asentity: AS
        for asn, asentity in self._asinfo.asas.items():
            co = cleanco.cleanco(asentity.name)
            # Set both company name and name of the AS
            # we will change companyname later (potentially)
            asentity.name = co.clean_name()
            # asentity.company = co.clean_name()
            asentity.presumtivecompany = co.clean_name()

            # Special case for Sweden and the US; since they show up alot
            # and share literals with others (i.e. "inc", "AB" etc)
            # HACK Perhaps fix to something more beautiful
            tmpco = co.country()  # Issue with calling country in cleanco
            # you can only call it once
            if tmpco:
                if "United States of America" in tmpco:
                    asentity.cc = "US"
                elif "Sweden" in tmpco:
                    asentity.cc = "SE"

            if asentity.cc is None and len(tmpco) == 1:
                # try with name ("United States", "Sweden")
                country = pycountry.countries.get(name=co.country[0])
                if not country:
                    # try with official name
                    # ("United States of America", "Royal Kingdom of Sweden")
                    country = pycountry.countries.get(official_name=co.country[0])

                if country:
                    asentity.cc = country.alpha_2

        # we have gone through once and updated
        # lets match
        compsdict = {ent.presumtivecompany: ent for ent in self._asinfo.asas.values()}
        complist = [k for k in compsdict]

        if len(complist) == 0:
            print("Empty company list! {:}".format(complist))
            return
        elif all(item == None for item in complist):
            print("All AS are None! {:}".format(complist))
            return

        companies = pd.Series(complist)
        # 0.40 for match is arbitrary, and choses since it seems to catch
        # "Amazon" vs "AMAZON-AES" and "Amazon Technologies"
        # HACK Motivate a better cutoff?
        matches = match_most_similar(masterlist, companies, min_similarity=0.40)
        # print(match_strings(masterlist, companies, min_similarity=0.05))
        # print(match_strings(companies, min_similarity=0.05))

        # print(complist)

        for tup in zip(complist, matches):
            # tup[0] org name, [1], matched name
            if tup[0] != tup[1]:
                # we only need to do something if they differ
                print("Merging presumtive company {:} with {:}".format(tup[0], tup[1]))
                ent: AS
                for ent in filter(
                    lambda x: x.presumtivecompany == tup[0], self._asinfo.ipas.values()
                ):
                    # print("Setting {:} to {:}".format(ent.name, tup[1]))
                    ent.company = tup[1]


if __name__ == "__main__":
    print("Running utilities as main, not really useful")

    import pprint

    ## example trace, one local, one well known, one in amazons network which is not announced, and DNs
    trace = (
        "2.18.74.134",
        [
            "192.168.0.1",
            "8.8.8.8",
            "52.93.2.80",
            "52.93.2.81",
            "2.18.74.134",
            "150.222.0.0",
        ],
    )

    pprint.pprint(trace)

    asl = ASNLookup()
    res = asl.lookupmanystr(trace[1])

    # pprint.pprint(res)
