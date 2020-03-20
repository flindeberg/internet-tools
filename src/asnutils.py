import ipaddress
from typing import Dict, List

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


class ASNLookup:
    """ Class for looking up ASN data """
    # currently based on pyasn, and has to be. They have the correct data
    __p = pyasn.pyasn("pyasn.dat", "pyasn.json")
    
    __urlrdap = "https://rdap.arin.net/registry/ip/{:}"

    def __init__(self):
        # load all names and pyas
        #self.p = pyasn.pyasn("pyasn.dat", "pyasn.json")
        None
        

    def lookupmanystr(self, ips: List[str]) -> AsInfo:
      
      ipstyped = list()
      for ip in ips:
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
          if ip.is_global():
            # we have a an IP which is global, i.e. should
            # be routable
            # tuple, 0 = asn, 1 = prefix
            r = __p.lookup(ip)
            if r[0] == None and r[1] == None:
              ## We do not have this ASN / prefix
              ## Lets create it
              url = __urlrdap.format(ip)
              with urllib.request.urlopen(url) as rdap:
                  data = json.loads(rdap.read().decode())
                  ## handle json
            
            elif r[0] == None or r[1] == None:
              ## We don't know this case, lets crash
              raise ValueError("Get either ASN or prefix, undefined case, failing fast and early (might be possible bug, undocumented case)")
            else:
              ## pyasn got a good match, lets use pyasn fully
              name = __p.get_as_name(r[0])
              asn = AS.CreateFromPyasnStr(ip, r[0], name)

              # lets create both dictionaries for now
              asinfo.ipas[ip] = asn
              asinfo.asas[r[0]] = asn
                  
          elif ip.is_link_local():
            None
                
          ## TODO already here, check that it is a good ip via ipaddress class
          ## i.e. not local, or otherwise reserved

            
                



        except ValueError as ve:
            print("Issues with ip-address '{:}': {:}".format(ip, ve))

      # return what we created 
      return asinfo

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
      
      
if __name__ == "__main__":
    print ("Running utilities as main, not really useful")
    
    ## example trace, one local, one well known, and DNs
    trace = ("2.18.74.134", ["192.168.0.1", "8.8.8.8", "2.18.74.134"])      