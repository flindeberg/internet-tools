# to allow for proper annotations and class structures
from __future__ import annotations
# Copyright (c) 2019 Fredrik Lindeberg <flindeberg@gmail.com>
# All rights reserved.

import functools
import ipaddress
import json
import os
import re
import sys
from dataclasses import dataclass
from enum import Enum
from subprocess import call
from typing import Dict, List, NamedTuple, Tuple
from urllib.parse import urlparse

import dns.resolver
import pyasn
import pycountry

from parallelltracert import TraceManager


class EdgeType(Enum):
    start = 0
    ihost = 1
    host = 2
    asn = 3
    cc = 4

# Manipulation of string and urls
class urlutils:

    @staticmethod
    def GetHostFromString(text: str) -> str:
        matches = re.findall('https?://.*?/', text,re.MULTILINE)
        parsedhost = ('{uri.netloc}'.format(uri=r) for r in (urlparse(line) for line in matches))
        return parsedhost

    @staticmethod
    def EnsureFullURI(text: str) -> str:
        ## reparse so have have an explicit http
        return urlparse(text, "http").geturl()


@dataclass
class EdgeTuple:
    ### Class to represent edges before drawing them
    ## Contains necessary meta-information
    node1: object
    node2: object
    node1type: EdgeType = None
    node2type: EdgeType = None
    edgeType: EdgeType = None
    data: object = None

    def __hash__(self):
        return self.node1.__hash__() + self.node2.__hash__() + self.edgeType.__hash__()

    def __eq__(self, x):
        return self.__hash__() == x.__hash__()

@dataclass
class AS:
    ### Class to represent-AS entities
    #self.name: str
    #self.asn: int
    #self.cc: str
    #self.exampleIp: str

    def __init__(self, name : str, asn : int, cc : str, exampleIp : str):
        self.name = name
        self.asn = asn
        self.cc = cc
        self.exampleIp = exampleIp

    @classmethod
    def CreateFromDict(cls, ip, d) -> AS: 
        ## just create and return
        ## d is assumed to come from cymruwhois
        return AS(d.owner,d.asn,d.cc,ip)

    @classmethod
    def CreateFromPyasnStr(cls, ip: str, asn: int, s: str) -> AS:
        ## create and return basically.
        if s is not None:
            country = pycountry.countries.get(alpha_2=s[-2:])
            if country is not None:
                country = country.name
        else: 
            country = ""

        return AS(s,asn,country,ip)


    def GetPrettyName(self) -> str:
        ## Gets a pretty representation of the AS
        ## for now "AS full name (ASN)", i.g. "Google LLC (1234)"
        return "{:} ({:})".format(self.name, self.asn)

    def __str__(self):
        return self.GetPrettyName()

## Type aliases
AsList = List[AS]
EdgeList = List[EdgeTuple]
AsDict = Dict[int, AS]
IpAsDict = Dict[str, AS]

class AsInfo(NamedTuple):
    ipas: AsDict = dict()
    asas: IpAsDict = dict()


class ASNLookup:
    """ Class for looking up ASN data """
    # currently based on pyasn, and has to be. They have the correct data

    def __init__(self):
        # load all names and pyas
        self.p = pyasn.pyasn("pyasn.dat", "pyasn.json")

    def lookupmany(self, ips: List[str]) -> AsInfo:
        
        asinfo = AsInfo()

        # go through ips and resolve  them
        for ip in ips:
            try:
                # tuple, 0 = asn, 1 = prefix
                r = self.p.lookup(ip)
                name = self.p.get_as_name(r[0])
                asn = AS.CreateFromPyasnStr(ip, r[0], name)

                # lets create both dictionaries for now
                asinfo.ipas[ip] = asn
                asinfo.asas[r[0]] = asn

            except ValueError as ve:
                print("Issues with ip-address '{:}': {:}".format(ip, ve))


        return asinfo

class HarResult:
    """ Class for storing data from har request """

    def __init__(self, file):
        # Do nothing!
        self._cookies = []
        self._hosts = []
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
    def hostTraceMap(self) -> Dict[str,List[str]]:
        return self._hostTraceMap

    @hostTraceMap.setter
    def hostTraceMap(self, value):
        self._hostTraceMap = value
    
    @property
    def asnTraceMap(self) -> Dict[str,AsList]:
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
    def hosts(self):
        return self._hosts

    @hosts.setter
    def hosts(self, value):
        self._hosts = value

    @property
    def asns(self) -> AsList:
        return self._asns

    @asns.setter
    def asns(self, value: AsList):
        self._asns = value

    @property
    def asnsAll(self) -> AsList:
        return self._asnsAll

    @asnsAll.setter
    def asnsAll(self, value: AsList):
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
        return '{:<28};{:>5};{:>5};{:>5};{:>5};{:>5};{:>30}'

    @staticmethod
    def HeaderPrint():
        # domain, cookies, hosts, autonomous systems for hosts, autonomous systems included those routed through, unique requests, starttime 
        print(HarResult.GetFormat().format("Domain","Ck", "Host", "Asns", "TASN", "Reqs", "Starttime"))

    def TablePrint(self):
        # domain : cookies : hosts : asns
        if (self.hasTime()):
            form = HarResult.GetFormat().format(self.file,len(self.cookies), len(self.hosts), len(self.asns), len(self.asnsAll), self.requests, self.start)
        else:
            form = HarResult.GetFormat().format(self.file,len(self.cookies), len(self.hosts), len(self.asns), len(self.asnsAll), self.requests, '-')
        print(form)

    @staticmethod
    def LatexTableStart():
        print (r'\begin{table}')
        print (r'  \begin{tabular}{lrrrr}')
        print (r'  Domain & Requests & Hosts & AS:s & AS:s r\\')
        print (r'  \hline')


    def LatexTableRow(self):
        print (r"  {:} & {:} & {:} & {:} & {:}\\".format(self.file.replace(".har",""), self.requests, len(self.hosts), len(self.asns), len(self.asnsAll)))

    @staticmethod
    def LatexTableCustomRow(name: str):
        print (r"  {:} & {:} & {:} & {:} & {:}\\".format(name, "-", "-", "-", "-"))

    @staticmethod
    def LatexTableEnd(caption: str="CAPTION", label: str="LABEL"):
        print (r'  \end{tabular}')
        print (r'  \caption{' + caption +  r'}')
        print (r'  \label{' + label + r'}')
        print (r'\end{table}')

    @classmethod
    def LatexTableTotalRow(cls, res):
        print (r'  \hline')
        print (r"  {:} & {:} & {:} & {:} & {:}\\".format(res.file,res.requests, len(res.hosts), len(res.asns), len(res.asnsAll)))

class Utils:

    @staticmethod
    def GetHarFile(url: str, harfile: str):
        #output = '-o ' + os.path.dirname(os.path.realpath(__file__)) + "/" + harfile
        output = '-o ' + harfile
        print("OUTPUT:" + output)
        print("URL:" + url)
        call(
            ['chrome-har-capturer',
            output, 
            url]
            , cwd=os.path.dirname(os.path.realpath(__file__))
            #, shell=True
            )


class CheckHAR:
    """Class for managing HAR-files"""


    def __init__(self): #, res: resolver.Resolver):
        # noting
        None
        self.nameip = dict()
        self.ipname = dict()
    
    def GetAsList(self, l : List[str]) -> AsInfo:
        #cymruClient = cymruwhois.Client()
        ## lookupmany only takes ip, so we have to convert from asn to ip and back..
        ## enumerate the list, else we get issues "sometimes"
        #ipsasndict = cymruClient.lookupmany_dict(l)
        #asnlist = []

        asnlookup = ASNLookup()

        return asnlookup.lookupmany(l)

        ## iterate through and create the list
        #for key in ipsasndict.keys():
        #    s = AS.CreateFromDict(key, ipsasndict[key])
        #    asnlist.append(s)
        #    ipsasndict[key] = s

        #return asnlist, ipsasndict

    def Load(self, file):
        # these are reloaded per HAR-file

        # some stupid string magic to keep compatability with earlier scripts
        self.result = HarResult(os.path.basename(file).replace(".har","").replace("www.",""))

        with open(file) as json_data:
            d = json.load(json_data)

            self.result.requests = len(d["log"]["entries"])

            if (len(d["log"]["pages"])> 0):
                self.result.start = d["log"]["pages"][0]["startedDateTime"]

            for entry in d["log"]["entries"]:
                parsedhost = urlutils.GetHostFromString(entry["request"]["url"])

                for h in parsedhost:
                    self.result.hosts.append(h)

                # Add all the cookies
                self.result.cookies.extend(entry["request"]["cookies"])
                self.result.cookies.extend(entry["response"]["cookies"])

            # magic done with hosts
            # get unique list, this is done via set
            self.result.hosts = list(set(self.result.hosts))

            print("Parser loaded, {:} hosts in total".format(len(self.result.hosts)))
            # for entry in self.result.hosts:
            #    print(entry)    

            locallistips = list()

            # go through all the hosts we use, and check paths and asns passed to get there
            for h in self.result.hosts:
                try:
                    ## find both a (ipv4) and aaaa (ipv6) records
                    dns.resolver
                    #ips = DNS.dnslookup(h, "a")
                    ips = (a.address for a in dns.resolver.query(h, "A"))
                    # IPv6 fails in the tracer. So lets skip it for now
                    #ips6 = (a.address for a in dns.resolver.query(h, "AAAA"))
                    #if ips6 is not None:
                    #    ips.extend(ips6)

                    for ip in ips:
                        try:
                            ## dnspython v2 vs v1.5 has different behaviour here, lets keep backwards comp

                            ## ip_inner is thrown and useless, but we need to check if "ip" is an actual ip 
                            ## in terms of format, and not a host (as the case in a cname -> cname -> a chain)
                            ip_inner = ipaddress.ip_address(ip)
                            ## here we know it is an ip
                            locallistips.append(ip_inner.exploded)
                            ## cache so we can do a reverse lookup quick
                            self.ipname[ip_inner.exploded] = h

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
                    print("Unexpected error:", sys.exc_info()[0])
                    print("Unexpected error:", sys.exc_info())
                    ## put it in the list, that way we still keep it even though we could not resolve it
                    self.ipname[h] = h

            # IPs we have found resources at 
            print("IP-addresses we have found resources at (duplicates removed):")
            print(set(locallistips))

            ## only host ips
            r = self.GetAsList(locallistips)
            self.result.asns = r.asas.values()

            # lets trace them all (requires root)
            tracedIps = TraceManager.TraceAll(locallistips)

            # traced ips
            #print(tracedIps)

            # get a dict describing it
            self.result.hostTraceMap = dict(zip(locallistips, tracedIps))

            # hosttracemap
            #print(self.result.hostTraceMap)

            # remove the unknown hosts
            if "*" in self.result.hostTraceMap.keys():
                del self.result.hostTraceMap["*"]


            if len(tracedIps) == 0:
                raise ValueError("We have ended up with 0(!) hosts, should not happen, check input!")

            # get asns from ips
            allIps = functools.reduce(list.__add__, tracedIps)
            ## now we get all ips, store all as and the ipas dict separately
            r = self.GetAsList(list(set(allIps)))
            self.result.asnsAll = r.asas.values()
            self.asndict = r.ipas

            # add a fake localhost in local network
            self.asndict["localhost"] = AS("local network", "NA", "", "10.0.0.1")

            # get hosts and ips
            # Gettings asns
            for tip in self.result.hostTraceMap.keys():
                filtered = list(filter(lambda x: x != "*",self.result.hostTraceMap[tip]))

                ## hostmap has hosts only
                ## asnmap has localhost, asns in the middle and hosts at the edges
                self.result.hostTraceMap[tip] = filtered
                self.result.asnTraceMap[tip] = list()
                for item in self.result.hostTraceMap[tip]:
                    tmpas = self.asndict[item]
                    if tmpas.name is None:
                        self.asndict[item].name = "N/A" 
                        self.asndict[item].asn = item

                    #if self.asndict[item].name == "N/A":
                    #    print("{:} is not announced by an AS".format(item))

                    self.result.asnTraceMap[tip].append(self.asndict[item])
                    ## TODO debug info
                    if item == "localhost":
                        print("localhost found {:}".format(self.result.hostTraceMap[tip]))

                ## Merge unknown AS into one for better overview
                last = None
                tracaslist = list()
                for item in self.result.asnTraceMap[tip]:
                    if last == None:
                        last = item
                        continue

                    # Check for match, if both N/A we have two unknown in a row, lets merge
                    if last.name == "N/A" and item.name == "N/A":
                        # create a new object, so we don't modify other references
                        newasn = AS(item.name, 1, item.cc, None)
                        newasn.asn = "{:}, {:}".format(last.asn, item.asn)
                        newasn.asn = newasn.asn[:30] + (newasn.asn[30:] and '..')
                        last = newasn
                        # now we "drop" item by not carrying it over in last
                    else:
                        # We append and continue.
                        tracaslist.append(last)
                        last = item

                ## add last
                tracaslist.append(last)

                #Update list    
                # print("Updating trace map, new:")
                # for ele in tracaslist:
                #     print(ele, sep=" -- ", end=" -- ")

                # print("")
                # print("--- end new --- start Old ---")
                # for ele in self.result.asnTraceMap[tip]:
                #     print(ele, sep=" -- ", end=" -- ")

                # print("")
                # print("--- end old ---")

                self.result.asnTraceMap[tip] = tracaslist

            # filter it so we only have unique values
            # asns where we fetched resources
            self.result.asns = self.result.asns
            # asns included those we were routed through
            self.result.asnsAll = self.result.asnsAll

            #print ("ASNS: {:} TOTAL ASNS {:}".format(len(self.result.asns), len(self.result.asnsAll)))

    def getEdges(self, dohosts: bool = False, useHostnames: bool = False) -> EdgeList:
        """
            Function for getting the edges for drawing a graph out of a HarResult
        """

        ## local network counter
        ## we should only get one, keeping as sanity check
        i = 1

        # make sure we get the right list to start with
        if dohosts:
            currentList = self.result.hostTraceMap
        else:
            currentList = self.result.asnTraceMap

        # the list of tuples we are going to return
        listTuples = list()

        ## current list is a dict<ip,list<trace>>
        for key in currentList.keys():
            # get the first and make it special
            current = "localhost"
            
            for point in currentList[key]:
                if point == None:
                    # If we don't have a nice value just continue
                    continue
   
                listTuples.append((current, point))

                current = point
            
            #if current != harRes.hostTraceMap[key][-1]:
                # i.e we are doing asn trace
                # then we apply the last host manually
                #listTuples.append((current,harRes.hostTraceMap[key][-1]))

            if current != key:
                # the last host didn't respond to ping
                # so we add it manually
                listTuples.append((current,key))

        ## Go through and change IPs into hostnames
        ## lets just cached lookups from previous
        reverselist = list()
        for element in listTuples:
            ## element is a tuple of ips and / or asn.
            left = element[0]
            right = element[1]

            et = EdgeType.ihost # assume indirect host
            lefttype = EdgeType.ihost
            righttype = EdgeType.ihost

            if (isinstance(left, AS) and left.asn == "NA"):
                ## fix it, its local network
                print ("local network found: {:}".format(left))
                left.name = "local network {:}".format(i)
                i += 1
                print ("local network found: {:}".format(left))

            if (isinstance(right, AS) and right.asn == "NA"):
                ## fix it, its local network
                print ("local network found: {:}".format(right))
                right.name = "local network {:}".format(i)
                i += 1
                print ("local network found: {:}".format(right))

            if isinstance(left, AS) and isinstance(right, AS):
                # edgetype is between as:es
                et = EdgeType.asn
            elif isinstance(left, AS): 
                # right is host
                if right in self.asndict.keys() and left.asn == self.asndict[right].asn:
                    et = EdgeType.host
                    righttype = EdgeType.host
                    
            elif isinstance(right, AS):
                # left is host
                if left in self.asndict.keys() and right.asn == self.asndict[left].asn:
                    et = EdgeType.host
                    lefttype = EdgeType.host
                
            # if we can find, replace, else just put it in again

            if left == "localhost":
                lefttype = EdgeType.start

            if isinstance(left, AS):
                ## replace AS with str
                if (left.cc != ""):
                    country = pycountry.countries.get(alpha_2=left.cc)
                    cc = left.cc
                    if country is not None:
                        cc = country.name

                    reverselist.append(EdgeTuple(cc, left.GetPrettyName(), EdgeType.cc, EdgeType.asn, edgeType=EdgeType.cc, data=left.asn))

                left = left.GetPrettyName()
                lefttype = EdgeType.asn
            elif left in self.ipname and useHostnames:
                ## convert ip to hostname
                left = self.ipname[left]

            if isinstance(right, AS):
                ## replace AS with str
                if (right.cc != ""):
                    country = pycountry.countries.get(alpha_2=right.cc)
                    cc = right.cc
                    if country is not None:
                        cc = country.name

                    reverselist.append(EdgeTuple(cc, right.GetPrettyName(), EdgeType.cc, EdgeType.asn, edgeType=EdgeType.cc, data=right.asn))

                right = right.GetPrettyName()
                righttype = EdgeType.asn
            elif right in self.ipname and useHostnames:
                ## convert ip to hostname
                right = self.ipname[right]

            reverselist.append(EdgeTuple(left,right, lefttype, righttype, edgeType=et))

        ## replace the list with our reverse list
        listTuples = list(set(reverselist))
        #listTuples = reverselist

        # return what we have
        return listTuples

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
    print ("Running utilities as main, not really useful")
