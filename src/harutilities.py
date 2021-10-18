#!/usr/bin/env python3
# to allow for proper annotations and class structures
from __future__ import annotations

# Copyright (c) 2019, 2020 Fredrik Lindeberg <flindeberg@gmail.com>
# All rights reserved.

import ipaddress
import json
import os
import re
import sys
from subprocess import call
from typing import Dict, List
from urllib.parse import urlparse

import dns.resolver
import pycountry

## local imports
from parallelltracert import TraceManager
import edgeutils
import asnutils
from edgeutils import EdgeTuple, EdgeType
from asnutils import AS

## Manipulation of string and urls
class urlutils:
    @staticmethod
    def GetHostFromString(text: str):
        matches = re.findall("https?://.*?/", text, re.MULTILINE)
        parsedhost = (
            "{uri.netloc}".format(uri=r) for r in (urlparse(line) for line in matches)
        )
        return parsedhost

    @staticmethod
    def EnsureFullURI(text: str) -> str:
        ## reparse so have have an explicit http
        if not "://" in text:
            text = "http://{:}".format(text)

        return urlparse(text).geturl()


class HarHost:
    """
    Class for storing host information, such as data transferred
    Also contains, after trace, information such as wether the trace was incomplete or full.
    """

    def __init__(self, host, transfersize: int = -1, realsize: int = -1):
        self._host = host
        self._transfersize = transfersize
        self._realsize = realsize
        # str -> list[str]
        self._ipstrace: Dict[ipaddress._BaseAddress, List[str]] = dict()
        # str -> list[str]
        self._astrace: Dict[ipaddress._BaseAddress, List[AS]] = dict()

        self._asnlookup = (
            asnutils.ASNLookup()
        )  ## Lets use one lookup util per instance of har host
        self._trace = (
            edgeutils.TraceType.missing
        )  # start with assuming that the trace is missing

    def setASNLookup(self, lookup: asnutils.ASNLookup):
        """Force a specific ASNLookup for this HarHost (could be useful for speed)"""
        self._asnlookup = lookup

    @property
    def ips(self):
        return list(str(key) for key in self._ipstrace)

    def get_trace(self, ip: str):
        return self._ipstrace[ip]

    @property
    def host(self):
        return self._host

    @property
    def size(self):
        if self._realsize > 0:
            return self._realsize
        else:
            return self._transfersize

    def merge(self, otherHost: HarHost):
        "merges other host into this host instance"
        if self._host != otherHost.host:
            raise ValueError("Hosts do not match!")

        self._transfersize += otherHost._transfersize
        self._realsize += otherHost._realsize

    def resolve(self):
        """Resolves this harhost via dns.resolver.query (dnspython).
            TODO Strategy pattern so we can change resolver if needed

        Args:
            None

        Returns:
            Nothing

        Raises:
            Nothing

        """

        try:
            ## find both a (ipv4) and aaaa (ipv6) records
            ##dns.resolver
            # ips = DNS.dnslookup(h, "a")
            ips = (a.address for a in dns.resolver.query(self._host, "A"))
            # IPv6 fails in the tracer. So lets skip it for now
            # ips6 = (a.address for a in dns.resolver.query(h, "AAAA"))
            # if ips6 is not None:
            #    ips.extend(ips6)

            for ip in ips:
                try:
                    ## dnspython v2 vs v1.5 has different behaviour here, lets keep backwards comp

                    ## ip_inner is thrown and useless, but we need to check if "ip" is an actual ip
                    ## in terms of format, and not a host (as the case in a cname -> cname -> a chain)
                    ip_inner = ipaddress.ip_address(ip)
                    ## here we know it is an ip
                    ## locallistips.append(ip_inner.exploded)
                    ## cache so we can do a reverse lookup quick
                    # ipname[ip_inner.exploded] = h.host

                    ## add it to the host as well
                    ## store it in the dict, which we populate later
                    self._ipstrace[ip_inner] = None

                except ValueError as e:
                    ## Probably a host (e.g. xxx.yyy.zzz.akamai.com or so via cname)
                    print("Not an IP, skipping: {:} ({:})".format(ip, e))
                except TypeError as e:
                    ## Something else is fishy
                    print("Not an IP, skipping: {:} ({:})".format(ip, e))
                except:
                    print("Unexpected error:", sys.exc_info())

        except:
            # DNS resolution messed up, such as host cannot be resolved
            # print("Unexpected error:", sys.exc_info()[0])
            print("Unexpected error (for {:}): {:}".format(self._host, sys.exc_info()))
            ## put it in the list, that way we still keep it even though we could not resolve it

    def getToTrace(self):
        """Helper func for future refactoring"""
        return self.ips

    def trace(self):
        """
        Does a trace route for all applicable IPS
        TODO Add support for IPv6, currently failing due to unknown reasons
        """
        ## TODO Tracemanager does not handle IP class!
        traces = TraceManager.TraceAll(self.ips)

        self.addTraces(traces)

    def addTraces(self, traces: Dict[ipaddress._BaseAddress, list]):
        """
        Helper function for adding traces back to HarHost
        """
        # TODO take care of the case if it is missing in traces?
        for key in self.ips:
            if key not in traces:
                raise ValueError("Could not find key '{:}' in traces!".format(key))
            ## Save the filtered list (i.e. we do not care about missing steps)
            ## "*" represents a ttl without response in the tracer

            ## HACK Should be fixed properly. It seems like it is very possible
            ## to get router to ignore ICMPs due to icmp storm,
            if traces[key][0] == "*":
                # lets replace it with a proper IP, if we have one
                for tracedip, tracelist in traces.items():
                    if tracelist[0] != "*":
                        traces[key][0] = tracelist[0]
                        # print("Updated trace to {:} with {:} at first hop"
                        #        .format(key, v[0]))
                        break

            filtered = list(filter(lambda x: x != "*", traces[key]))
            iplist = list(ipaddress.ip_address(x) for x in filtered)
            ## Set the resolves ip last of the trace times out, this ensures proper AS match
            if iplist[-1] != ipaddress.ip_address(key):
                iplist.append(ipaddress.ip_address(key))
                print("Added {:} last to {:}".format(ipaddress.ip_address(key), ipaddress.ip_address(key)))
            
            self._ipstrace[ipaddress.ip_address(key)] = iplist

            ## Set the trace status, will be used for coloring later
            self._trace = edgeutils.TraceType.getTraceStatus(traces[key])

    def populateAsns(self):
        """
        Looks up ASNS data
        """

        # get an instance of the util, and look up the necessary ips
        asn: asnutils.ASNLookup
        if self._asnlookup:
            asn = self._asnlookup
        else:
            asn = asnutils.ASNLookup()
        # many will just have one ip, but for those which have many we will trace many
        for key, ips in self._ipstrace.items():
            asinfo = asn.lookupmanystr(ips)

            # build a new list of visited AS along the line
            self._astrace[key] = list()

            for ip in ips:
                # fetch the matching AS, it might be "bad", i.e. missing name if it doesn't exist
                if ip in asinfo.ipas:
                    # if we cant match ip, just skip it
                    refas = asinfo.ipas[ip]
                    self._astrace[key].append(refas)
                    # print("Added {:} to {:}".format(refas, ip))
                else:
                    print("Could not find AS for {:}.".format(ip))

    def getedges(self) -> asnutils.EdgeList:
        """
        Get a list of edges from the current host object.
        Edges are entities made for graphing, and as such contain much less data than the HarHost object
        """
        # Start with "localhost"
        edges = list()

        for ipkey, ips in self._astrace.items():
            # ipkey is ip
            lastNode = ("localhost", EdgeType.start)
            # annotate for type help
            current: AS
            for current in ips:
                # current is here an AS
                try:
                    country = pycountry.countries.get(alpha_2=current.cc)

                    # use lastNode, as well as the current one
                    # current is ASN, lastNode might be "localhost" or ASN
                    # doublecheck that we are not referencing ourselves
                    if lastNode[0] != current.GetPrettyName():
                        edges.append(
                            EdgeTuple(
                                lastNode[0],
                                current.GetPrettyName(),
                                lastNode[1],
                                EdgeType.asn,
                                lastNode[1],
                                data=self.size,
                            )
                        )

                    if country is not None:  # only add countries which exist
                        # add country connection as well
                        edges.append(
                            EdgeTuple(
                                country.name,
                                current.GetPrettyName(),
                                EdgeType.cc,
                                EdgeType.asn,
                                EdgeType.cc,
                                data=current.asn,
                            )
                        )

                    # Handle company if present
                    if current.company is not None:
                        edges.append(
                            EdgeTuple(
                                current.company,
                                current.GetPrettyName(),
                                EdgeType.company,
                                EdgeType.asn,
                                EdgeType.company,
                            )
                        )

                    # prepare for next round
                    lastNode = (current.GetPrettyName(), EdgeType.asn)
                except LookupError as e:
                    ## Something else is fishy
                    print("Not an country, skipping: '{:}' ({:})".format(current.cc, e))
                except:
                    print("Unexpected error:", sys.exc_info())

            # If we have a full trace its a "host", else its an
            # "indirect host" (i.e. ihost)
            hostedge: EdgeType
            hostblobb: EdgeType

            if (
                self._trace == edgeutils.TraceType.full
                or self._trace == edgeutils.TraceType.fullbutmid
            ):
                hostedge = EdgeType.host
                hostblobb = EdgeType.host
            else:
                hostedge = EdgeType.ihost
                hostblobb = EdgeType.ihost

            # We have added all but lastNode -> final host (IP)
            edges.append(
                EdgeTuple(lastNode[0], self._host, lastNode[1], hostblobb, hostedge)
            )

        # import pprint
        # pprint.pprint(edges)

        # Now we have done all combinations
        return edges


HostDict = Dict[ipaddress._BaseAddress, HarHost]


class HarResult:
    """Class for storing data from har request"""

    def __init__(self, file):
        # Do nothing!
        self._cookies = []
        self._hosts = dict()
        # all as with resources
        self._asns = []
        # all as we have traversed
        self._asnsAll = []
        self._requests = 0
        self._file = file
        self._start = None
        self._hostTraceMap = None
        self._asnTraceMap = dict()

    def hasTime(self):
        return self._start != None

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value):
        self._start = value

    @property
    def hostTraceMap(self) -> Dict[str, List[str]]:
        return self._hostTraceMap

    @hostTraceMap.setter
    def hostTraceMap(self, value):
        self._hostTraceMap = value

    @property
    def asnTraceMap(self) -> Dict[str, asnutils.AsList]:
        return self._asnTraceMap

    @asnTraceMap.setter
    def asnTraceMap(self, value):
        self._asnTraceMap = value

    @property
    def cookies(self):
        return self._cookies

    @cookies.setter
    def cookies(self, value):
        self._cookies = value

    @property
    def hosts(self) -> Dict[str, HarHost]:
        return self._hosts

    @hosts.setter
    def hosts(self, value: Dict[str, HarHost]):
        self._hosts = value

    @property
    def asns(self) -> asnutils.List:
        return self._asns

    @asns.setter
    def asns(self, value: asnutils.AsList):
        self._asns = value

    @property
    def asnsAll(self) -> asnutils.AsList:
        return self._asnsAll

    @asnsAll.setter
    def asnsAll(self, value: asnutils.AsList):
        self._asnsAll = value

    @property
    def requests(self):
        return self._requests

    @requests.setter
    def requests(self, value):
        self._requests = value

    @property
    def file(self):
        return self._file

    ### Pretty-print related to latex table format

    @staticmethod
    def GetFormat():
        return "{:<28};{:>5};{:>5};{:>5};{:>5};{:>5};{:>30}"

    @staticmethod
    def HeaderPrint():
        # domain, cookies, hosts, autonomous systems for hosts, autonomous systems included those routed through, unique requests, starttime
        print(
            HarResult.GetFormat().format(
                "Domain", "Ck", "Host", "Asns", "TASN", "Reqs", "Starttime"
            )
        )

    def TablePrint(self):
        # domain : cookies : hosts : asns
        if self.hasTime():
            form = HarResult.GetFormat().format(
                self.file,
                len(self.cookies),
                len(self.hosts),
                len(self.asns),
                len(self.asnsAll),
                self.requests,
                self.start,
            )
        else:
            form = HarResult.GetFormat().format(
                self.file,
                len(self.cookies),
                len(self.hosts),
                len(self.asns),
                len(self.asnsAll),
                self.requests,
                "-",
            )
        print(form)

    @staticmethod
    def LatexTableStart():
        print(r"\begin{table}")
        print(r"  \begin{tabular}{lrrrr}")
        print(r"  Domain & Requests & Hosts & AS:s & AS:s r\\")
        print(r"  \hline")

    def LatexTableRow(self):
        print(
            r"  {:} & {:} & {:} & {:} & {:}\\".format(
                self.file.replace(".har", ""),
                self.requests,
                len(self.hosts),
                len(self.asns),
                len(self.asnsAll),
            )
        )

    @staticmethod
    def LatexTableCustomRow(name: str):
        print(r"  {:} & {:} & {:} & {:} & {:}\\".format(name, "-", "-", "-", "-"))

    @staticmethod
    def LatexTableEnd(caption: str = "CAPTION", label: str = "LABEL"):
        print(r"  \end{tabular}")
        print(r"  \caption{" + caption + r"}")
        print(r"  \label{" + label + r"}")
        print(r"\end{table}")

    @classmethod
    def LatexTableTotalRow(cls, res):
        print(r"  \hline")
        print(
            r"  {:} & {:} & {:} & {:} & {:}\\".format(
                res.file, res.requests, len(res.hosts), len(res.asns), len(res.asnsAll)
            )
        )


class Utils:
    @staticmethod
    def GetHarFile(url: str, harfile: str):
        # output = '-o ' + os.path.dirname(os.path.realpath(__file__)) + "/" + harfile
        output = "-o " + harfile
        print("OUTPUT:" + output)
        print("URL:" + url)
        call(
            ["chrome-har-capturer", output, url],
            cwd=os.path.dirname(os.path.realpath(__file__))
            # , shell=True
        )


class CheckHAR:
    """Class for managing HAR-files"""

    def __init__(self):  # , res: resolver.Resolver):
        # noting
        None
        self.nameip = dict()
        self.ipname = dict()
        # Lets have a lookup we can share for faster lookups
        self._asnlookup = asnutils.ASNLookup()

    def GetAsList(self, l: List[str]) -> asnutils.AsInfo:
        # cymruClient = cymruwhois.Client()
        ## lookupmany only takes ip, so we have to convert from asn to ip and back..
        ## enumerate the list, else we get issues "sometimes"
        # ipsasndict = cymruClient.lookupmany_dict(l)
        # asnlist = []

        asnlookup = asnutils.ASNLookup()

        return asnlookup.lookupmany(l)

        ## iterate through and create the list
        # for key in ipsasndict.keys():
        #    s = AS.CreateFromDict(key, ipsasndict[key])
        #    asnlist.append(s)
        #    ipsasndict[key] = s

        # return asnlist, ipsasndict

    def Load(self, file):
        # these are reloaded per HAR-file

        # some stupid string magic to keep compatability with earlier scripts
        self.result = HarResult(
            os.path.basename(file).replace(".har", "").replace("www.", "")
        )

        with open(file) as json_data:
            d: dict = json.load(json_data)

            self.result.requests = len(d["log"]["entries"])

            if len(d["log"]["pages"]) > 0:
                self.result.start = d["log"]["pages"][0]["startedDateTime"]

            entry :dict
            for entry in d["log"]["entries"]:
                
                parsedhost = urlutils.GetHostFromString(entry["request"]["url"])
                realsize = (
                    (entry["request"].get("headersSize", 0) or 0)
                    + (entry["request"].get("bodySize", 0) or 0)
                    + (entry["response"].get("headersSize", 0) or 0)
                    + (entry["response"].get("bodySize", 0) or 0)
                )
                if "_transferSize" in entry["response"]:
                    transfersize = entry["response"]["_transferSize"]
                else:
                    transfersize = 0

                for h in parsedhost:
                    ## Create a host object matching the host
                    hh = HarHost(h, transfersize=transfersize, realsize=realsize)
                    ## lets use our set lookup for speed
                    hh.setASNLookup(self._asnlookup)

                    ## if we have the host, just update it
                    ## if we don't, add it
                    if h in self.result.hosts:
                        self.result.hosts[h].merge(hh)
                    else:
                        self.result.hosts[h] = hh

                # Add all the cookies
                self.result.cookies.extend(entry["request"]["cookies"])
                self.result.cookies.extend(entry["response"]["cookies"])

            print("Parser loaded, {:} hosts in total".format(len(self.result.hosts)))

    def cook(self):
        """Cooks the the Har so we can get the edges. Has to be called prior to getEdges"""

        # type hint them, we are reusing them
        key: str
        value: HarHost

        # go through all the hosts we use, and check paths and asns passed to get there
        print("Starting to resolve hosts")
        for key, value in self.result.hosts.items():
            value.resolve()

        # Make sure we trace all ips
        ipstotrace = list()
        print("Collecting IPs to trace")
        for key, value in self.result.hosts.items():
            # self.result.hosts[key].trace()
            ipstotrace.extend(value.getToTrace())

        ## Trace all at the same time (due to GIL issues with Python...)
        print("Starting to trace hosts")
        traces = TraceManager.TraceAll(set(ipstotrace))

        print("Adding traces to hosts")
        for key, value in self.result.hosts.items():
            value.addTraces(traces)

        # Now we have all hosts, their traceroutes (hopefully somewhat populated),
        # now it is time to resolve their autonomous systems
        print("Starting to resolve autonomous systems from traces")
        for key, value in self.result.hosts.items():
            value.populateAsns()

        # HACK Call clean on the ASN lookup
        self._asnlookup.clean()

    def getEdges(
        self, dohosts: bool = False, useHostnames: bool = False
    ) -> asnutils.EdgeList:
        """
        Gets all edges in asnutils.EdgeList.
        Has to be called after 'cook()'
        """

        print("Constructing edges from routing information")
        # force a set so we dont get duplicates
        edges = set(
            [
                edge
                for key in self.result.hosts
                for edge in self.result.hosts[key].getedges()
            ]
        )

        # import pprint
        # pprint.pprint(edges)

        return edges

    def GetHosts(self):
        return self.result.hosts

    def GetCookies(self):
        return self.result.cookies

    def GetAsns(self):
        return self.result.asns

    def GetAllAsns(self):
        return self.result.asnsAll

    def GetRequests(self):
        return self.result.requests

    def PrettyPrint(self):
        print("Report for {:}".format(self.result.file))
        print("Nr of cookies: " + str(len(self.GetCookies())))
        print("Nr of hosts: " + str(len(self.GetHosts())))
        print("Nr of asns: " + str(len(self.GetAsns())))
        print("Nr of asns inc routing: " + str(self.GetAllAsns()))
        print("Nr of requests: " + str(self.GetRequests()))

    def GetResult(self):
        return self.result


if __name__ == "__main__":
    print("Running utilities as main, using fixed trace list")

    ## example trace, one local, one well known, and DNs
    # trace = ("2.18.74.134", ["192.168.0.1", "8.8.8.8", "2.18.74.134"])

    # hosts = ["www.dn.se", "www.svd.se", "www.happygreen.com"]
    import pprint

    hh = HarHost("www.happygreen.com")
    print("Starting to resolve")
    hh.resolve()

    print("Starting to trace")
    hh.trace()

    print("Starting to populate asns")
    hh.populateAsns()

    pprint.pprint(hh)

    print("Getting edges")

    pprint.pprint(hh.getedges())
    pprint.pprint(hh._ipstrace)
    pprint.pprint(hh._astrace)
