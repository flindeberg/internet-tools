#!/usr/bin/env python3
import ipaddress
from typing import Dict, List, NamedTuple
from dataclasses import dataclass
import pyasn
import pycountry
import urllib.request
from urllib.parse import urlparse
import json

import edgeutils

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
  def CreateFromDict(cls, ip, d): 
    ## just create and return
    ## d is assumed to come from cymruwhois
    return AS(d.owner,d.asn,d.cc,ip)

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

    return AS(s,asn,country,ip)


  def GetPrettyName(self) -> str:
    ## Gets a pretty representation of the AS
    ## for now "AS full name (ASN)", i.g. "Google LLC (1234)"
    if self.cc == "" or self.cc == None:
      return '{:}\n({:})'.format(self.name, self.asn)
    ## return the country code as well if we have it
    return '{:}\n({:}, {:})'.format(self.name, self.asn, self.cc)

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
  # ASN to AS mappings
  ipas: AsDict = dict()
  # IP to AS mapping
  asas: IpAsDict = dict()

@dataclass
class ASFind:
  def __init__(self, asns : List[int], start : ipaddress._BaseAddress, end : ipaddress._BaseAddress):
    super().__init__()
    
    self._CIDRs = list(ipaddress.summarize_address_range(start, end))
    self._ASNs = asns
  
  @property
  def CIDRs(self):
    return self._CIDRs
  
  @property
  def ASNs(self):
    return self._ASNs
  
  def contains(self, ip : ipaddress._BaseAddress) -> List[int]:
    # check if we have a CIDR containing the ip
    # if we do, return the first asn
    for cidr in self.CIDRs:
      if ip in cidr:
        ## just assume the first is the best..
        return self.ASNs
    
    ## no match, lets return None
    return None

class ASNLookup:
  """ Class for looking up ASN data """
  # currently based on pyasn, and has to be. They have the correct data
  __p = pyasn.pyasn("pyasn.dat", "pyasn.json")
  
  ## Url from which to do a curl for rdap data
  __urlrdap = "https://rdap.arin.net/registry/ip/{:}"
  
  ## list with unnannounced AS which we have figured out
  __unannounced = list()

  def __init__(self):
    # load all names and pyas
    #self.p = pyasn.pyasn("pyasn.dat", "pyasn.json")
    None
    

  def lookupmanystr(self, ips: List[str]) -> AsInfo:
    
    ipstyped = list()
    for ip in set(ips): ## remove duplicates
      try:
        ## translate to typed
        ipc = ipaddress.IPv4Address(ip)
        ipstyped.append(ipc)
      except ValueError as ve:
        print("Issues with ip-address '{:}': {:}".format(ip, ve))
        
    return self.lookupmany(ipstyped)
      
    
  def lookupmany(self, ips: List[ipaddress.IPv4Address]) -> AsInfo:
    asinfo = AsInfo()
    
    # go through ips and resolve  them
    for ip in ips:
      try:
        ## we know we have proper IPv4 address here

        # Sanity checks so we know what to do
        # Only check global and private ips
        if ip.is_global:
          # we have a an IP which is global, i.e. should
          # be routable
          # tuple, 0 = asn, 1 = prefix
          r = ASNLookup.__p.lookup(ip.exploded)
          
          if r[0] == None and r[1] == None:
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
              print("IP-address {:} is not announced, looking for it with RDAP towards ARIN.".format(ip.exploded))
              url = ASNLookup.__urlrdap.format(ip)
              with urllib.request.urlopen(url) as rdap:
                data = json.loads(rdap.read().decode())
                ## handle json
                start = ipaddress.ip_address(data["startAddress"]) #ip
                end = ipaddress.ip_address(data["endAddress"]) #ip

                if "arin_originas0_originautnums" in data:
                  asns = data["arin_originas0_originautnums"] # list
                  
                  ## create and add to unannounced
                  asf = ASFind(asns, start, end)
                  ASNLookup.__unannounced.append(asf)
                  
                  ## update our internal mappings
                  for a in asns:
                    asn = AS.CreateFromPyasnStr(ip, a, ASNLookup.__p.get_as_name(asns[0]))
                    asinfo.ipas[ip] = asn
                    asinfo.asas[a] = asn
                    print("Added {:} ({:}) which covers {:} to {:}".format(asn.name, asn.asn, start.exploded, end.exploded))
                  
                else:
                  # we do not have an ASN!
                  # lets create a negative number representing it
                  if len(asinfo.asas) > 0:
                    asns = [min(min([i for i in asinfo.asas if isinstance(i, int)]) - 1, -1)]
                  else:
                    asns = [-1]

                  ## create and add to unannounced even if we do not have it
                  asf = ASFind(asns, start, end)
                  ASNLookup.__unannounced.append(asf)
                  
                  # lets also use name and country from whois
                  name = data["name"]
                  cc = data["country"]
                  
                  # Create a temporary name from CIDRS
                  cidrs = [cidr.exploded for cidr in ipaddress.summarize_address_range(start, end)]
                  tmpname = ", ".join(cidrs)

                  ## update our internal mappings
                  asn = AS(name, asns[0], cc, ip)
                  #asn = AS.CreateFromPyasnStr(ip, asns[0], "{:}, {:}".format(name, cc))
                  asinfo.ipas[ip] = asn
                  asinfo.asas[asns[0]] = asn
                  print("Added {:} ({:}) which covers {:} to {:}".format(asn.name, asn.asn, start.exploded, end.exploded))
                
          elif r[0] == None or r[1] == None:
            ## We don't know this case, lets crash
            raise ValueError("Get either ASN or prefix, undefined case, failing fast and early (might be possible bug, undocumented case)")
          
          else:
            ## pyasn got a good match, lets use pyasn fully
            ## first, lets check if we have it already
            if r[0] in asinfo.asas:
              # we have it, add ip and we are done
              asinfo.ipas[ip] = asinfo.asas[r[0]] # ip -> as
            else:
              # We do not already have it, we need to create one
              ## __p is the global pyasn instance, contents are cached and loaded to memory
              name = ASNLookup.__p.get_as_name(r[0])
              asn = AS.CreateFromPyasnStr(ip, r[0], name) # really an as and not asn, but "as" is protected in Python

              # lets create both dictionaries for now
              asinfo.ipas[ip] = asn # ip -> as
              asinfo.asas[r[0]] = asn # 
                
        elif ip.is_private:
          ## local ip-address
          print("IP-address '{:}' is a private network.".format(ip))

          cidr = ipaddress.ip_network(ip).supernet(new_prefix=24)

          name = "Private network {:}".format(cidr)
          if name not in asinfo.asas:
            asn = AS.CreateFromPyasnStr(ip, 0, name) # really an as and not asn, but "as" is protected in Python
            # lets create both dictionaries for now
            asinfo.ipas[ip] = asn # ip -> as
            asinfo.asas[name] = asn # 
          else:
            ## for now, assume only one local network and reuse it
            asinfo.ipas[ip] = asinfo.asas[name] # ip -> as
            
        else:
          print("IP-address '{:}' is neither global nor local, skipping for now.".format(ip))

        
      except ValueError as ve:
          print("Issues with ip-address '{:}': {:}".format(ip, ve))

    # return what we created 
    return asinfo

      
      
if __name__ == "__main__":
  print ("Running utilities as main, not really useful")
  
  ## example trace, one local, one well known, one in amazons network which is not announced, and DNs
  trace = ("2.18.74.134", ["192.168.0.1", "8.8.8.8", "52.93.2.80", "52.93.2.81", "2.18.74.134"])      
  
  asl = ASNLookup()
  res = asl.lookupmanystr(trace[1])
  
  print(res)