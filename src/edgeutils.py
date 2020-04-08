from enum import Enum
from dataclasses import dataclass

class TraceType(Enum):
    full = 0 # a full and complete trace
    fullbutend = 1 # all missing hosts are at the end
    fullbutmid = 2 # all missing hosts are in the middle
    missing = 3 # some other form

    @classmethod
    def getTraceStatus(cls, trace: list):
        ## Set the tracing flags
        if "*" not in trace:
            # No stars, it is a full trace
            return TraceType.full
        elif trace[-1] != "*":
            # We have the end, so we are missing mid
            return TraceType.fullbutmid
        else:
            # lets check if they are all at the end
            # shallow copy to be on the safe side (remove later?)
            rev = trace.copy()
            while rev[-1] == "*":
                rev = rev[:-1]
            # now we have removed the end *:s, lets see if we still have any
            return TraceType.fullbutend if "*" not in rev else TraceType.missing

class EdgeType(Enum):
    start = 0
    ihost = 1
    host = 2
    asn = 3
    cc = 4

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

