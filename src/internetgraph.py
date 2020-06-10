# Copyright (c) 2019 Fredrik Lindeberg <flindeberg@gmail.com>
# All rights reserved.

import math
from dataclasses import dataclass
from itertools import chain
from typing import Dict, List

import matplotlib.pyplot as plt
import matplotlib.colors as clr
import matplotlib.cm as cm
import networkx as nx
import numpy as np

import asnutils
import harutilities
from harutilities import EdgeType

## To rename files / eps / etc
from pathlib import Path

@dataclass
class DrawWrapper:
    ## Contains nodes, colors, sizes etc
    nodes: List[str]
    edges: list
    label: str
    shape: str
    textsize: int = 4
    nodesize: int = 160
    color: str = "blue"

    def LabelDict(self) -> dict:
        # return a label dictionary
        return {n:n for n in self.nodes}

    def HasLabels(self) -> bool:
        return self.nodes is not None

    def HasNodes(self) -> bool:
        return self.nodes is not None

    def HasEdges(self) -> bool:
        return self.edges is not None

def is_digit(x):
    # check if it is a digit
    return (isinstance(x, str) and x.isdigit()) or isinstance(x, int)

def is_cc(x):
    # check if two letter string
    return (isinstance(x, str) and len(x) == 2)

def is_integer(x):
    # check if input is integer
    return type(x) is int

def get_color(nr: int, all: int):
    # some magic to crate a redish hue mixed with some color
    fact = float(nr) / float(all)
    ## a bit fo magic to create a 2-d vector
    ## needed for numpy colors
    res = np.array(cm.autumn(fact))[None, :]
    return res

def draw_graph(graph: asnutils.EdgeList, file: str, graph_layout='sfdp') -> List[Path]:

    # just dump it
    #print(graph)

    # create networkx graph
    G=nx.Graph()
    #G=nx.MultiDiGraph()

    # save the nodes for later
    nodes = list()

    nodelist = {e : list() for e in EdgeType}
    #nodelist = {EdgeType.asn : list(), EdgeType.cc : list(), EdgeType.host : list(), EdgeType.ihost : list(), EdgeType.start : list(), EdgeType.company : list()}

    # add edges
    for edge in graph:
        
        ## assume ihost (i.e. indirect host, trace failed)
        weight = 2
        length = 2
        if edge.edgeType == EdgeType.cc:
            # lower weight for country codes
            # should not organize on their behalf
            weight = 24
            length = 6
        elif edge.edgeType == EdgeType.asn:
            weight = 2
            length = 5  
        elif edge.edgeType == EdgeType.host:
            weight = 8
            length = 1.5
        elif edge.edgeType == EdgeType.company:
            weight = 20
            length = 4

        # add nodes and edges to graph model
        G.add_edge(edge.node1, edge.node2, weight=weight, length=length, len=length)
        G.add_node(edge.node1)
        G.add_node(edge.node2)


        # add to typed list so we have draw control (i.e. different colors and so forth)
        nodes.append(edge.node1)
        nodes.append(edge.node2)

        nodelist[edge.node1type].append(edge.node1)
        nodelist[edge.node2type].append(edge.node2)


    edges = dict()
    # get all edges, and purge doubles for performance (drawing takes significant CPU)
    ## filter out edges
    for e in list(EdgeType):
        edges[e] = list(set((r.node1, r.node2) for r in filter(lambda x: x.edgeType == e, graph)))

    # Get only unique values
    nodes = list(set(nodes))

    # Create wrappers for the different types
    # also set drawing rules (colors, etc)
    wrappers = dict()
    # static wrappers (start, hosts and indirect hosts)
    wrappers[EdgeType.ihost] = DrawWrapper(list(set(nodelist[EdgeType.ihost])), edges[EdgeType.ihost], "Indirect hosts", "o", textsize=3, nodesize=100, color="skyblue")
    wrappers[EdgeType.host] = DrawWrapper(list(set(nodelist[EdgeType.host])), edges[EdgeType.host], "Hosts", "o", textsize=3, nodesize=100, color="blue")
    wrappers[EdgeType.start] = DrawWrapper(nodelist[EdgeType.start], edges[EdgeType.start], "Start", "p", textsize=4, nodesize=160, color="yellow")

    # add those without country
    nodelist[EdgeType.asn] = set(nodelist[EdgeType.asn])

    # figure out the number of countries involved (on paper), if any
    countries = set(t.node1 for t in filter(lambda x: x.edgeType == EdgeType.cc, graph))
    # index is used for coloring, color "0" is already taken by "IP not announced and insterad put inautomagic AS" 
    # (harutils create "virtual" AS where multiple hosts / IPs are bundled together to make the graph nicer)
    index = 1
    index_tot = len(countries) + 1
    for country in countries:
        ASNs = set(t.node2 for t in filter(lambda x: x.edgeType == EdgeType.cc and x.node1 == country, graph))
        
        for AS in ASNs:
            if AS in nodelist[EdgeType.asn]:
                nodelist[EdgeType.asn].remove(AS) 

        wrappers[country + "_ASN" if country else "unknown_ASN"] = DrawWrapper(ASNs, None, "ASN", "o", textsize=4, nodesize=300, color=get_color(index, index_tot))
        # TODO Draw countries here as well, ie match color for AS and country diamonds
        # wrappers[country + "_CC"] = DrawWrapper(list(set(nodelist[EdgeType.cc])), edges[EdgeType.cc], "Countries", "d", textsize=5, nodesize=400, color=get_color(index, len(countries)))
        index = index + 1
        

    # dynamic wrappers, i.e. asn per cc
    wrappers[EdgeType.asn] = DrawWrapper(list(set(nodelist[EdgeType.asn])), edges[EdgeType.asn], "ASN", "o", textsize=4, nodesize=300, color="red")
    wrappers[EdgeType.cc] = DrawWrapper(list(set(nodelist[EdgeType.cc])), edges[EdgeType.cc], "Countries", "d", textsize=5, nodesize=400, color="green")

    wrappers[EdgeType.company] = DrawWrapper(list(set(nodelist[EdgeType.company])), edges[EdgeType.company], "Companies", "d", textsize=5, nodesize=400, color="purple")

    # All AS same color
    #wrappers["ASNedges"] = DrawWrapper(None, edges[EdgeType.asn], "ASN", "o", textsize=4, nodesize=300, color="red")

    # these are different layouts for the network you may try
    # for now defaulting to graphviz
    if graph_layout == 'sfdp':
        ## Default to using graphviz, better and faster..
        graph_pos=nx.drawing.nx_agraph.graphviz_layout(G, prog='neato', root="localhost", args="-Gmaxiter=200")
    elif graph_layout == 'spring':
        #graph_pos=nx.spring_layout(G, pos={startNode[0]: (0.5,0.5)}, fixed=startNode, iterations=150, scale=1)
        graph_pos=nx.spring_layout(G, iterations=150, scale=1)
    elif graph_layout == 'spectral':
        graph_pos=nx.spectral_layout(G)
    elif graph_layout == 'random':
        graph_pos=nx.random_layout(G)
    else:
        #graph_pos=nx.kamada_kawai_layout(G)
        graph_pos=nx.shell_layout(G)

    ## set size before draw
    # lets scale with the square of number of nodes
    # (i.e. space per node stays constant)
    figs = int(math.sqrt(len(nodes))) + 2
    plt.figure(figsize=(figs, figs))

    # generic defaults
    node_alpha=0.3
    edge_alpha=0.3
    edge_tickness=1
    text_font='sans-serif'

    # draw edges
    for i in wrappers.values():
        if i.HasEdges():
            nx.draw_networkx_edges(G,graph_pos,width=edge_tickness, edgelist=i.edges,
                                   alpha=edge_alpha,edge_color=i.color)

    # draw nodes
    for i in wrappers.values(): 
        if i.HasNodes():
            nx.draw_networkx_nodes(G,graph_pos,node_size=i.nodesize, nodelist=i.nodes, node_shape=i.shape,
                                   alpha=node_alpha, node_color=i.color, label=i.label)

   
    # draw labels
    for i in wrappers.values(): 
        if i.HasLabels():
            nx.draw_networkx_labels(G, graph_pos, labels=i.LabelDict(),font_size=i.textsize,
                                    font_family=text_font)


    plt.axis('off')   
    
    #plt.show()
    #plt.savefig(file, format='png', dpi=1000, pad_inches=0.3)

    # loop over file endings
    p = Path(file)
    # png gives useful bitmap which can be opened everywhere
    # svg is better
    types = ["png","svg"]
    files =[]
    for t in types:
        f = p.with_suffix(".{:}".format(t))
        files.append(f)
        plt.savefig(f, format=t, dpi=1000, pad_inches=0.3)
        print("Graph-{:} saved to {:}".format(t,f))
    
    #plt.savefig(p.with_suffix(".png"), format='png', dpi=350, pad_inches=0.3)
    #plt.savefig(p.with_suffix(".svg"), format='svg', dpi=350, pad_inches=0.3)
    #plt.savefig(p.with_suffix(".eps"), format='eps', dpi=350, pad_inches=0.3)
    plt.gcf().clear()
    return files
    

if __name__ == "__main__":
    print("Did you really intend to run this as main?")
