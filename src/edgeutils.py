from enum import Enum
from dataclasses import dataclass

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

