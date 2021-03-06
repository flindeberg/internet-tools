#!/bin/env python3

# Copyright (c) 2019, 2020 Fredrik Lindeberg <flindeberg@gmail.com>
# All rights reserved.

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from shutil import copyfile

from datetime import datetime

from elevate import elevate

import harutilities
import internetgraph
import parallelltracert
from harutilities import urlutils
from urllib.parse import urlparse


"""
 Module for generating graphs of website dependencies. Useful for illustrating
 the complexity of the Internet by showing how the web# uses the Internet.
"""


def main(arg=None):

    # no args, lets fetch from commandline
    parser = argparse.ArgumentParser(
        description="Draw tracemaps based on a set of hosts"
    )

    parser.add_argument(
        "-s",
        "--separate",
        action="store_true",
        help="run separate instances per website (i.e. not all in one graph)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="does not try to open graph in default program after run",
    )
    parser.add_argument(
        "-c",
        "--clean",
        action="store_true",
        help="runs cleanly (i.e. does not check asn owners etc), but still needs DNS",
    )
    parser.add_argument("-n", "--iterations", type=int, default=1)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-f", "--file", help="path to file with hosts")
    group.add_argument("-w", "--hostnames", nargs="+", help="list of hosts to query")
    group.add_argument("-e", "--har", help="har-file to use directly")

    parser.add_argument(
        "-o", "--output", help="output directory (everything goes here)"
    )

    parser.add_argument(
        "-p",
        "--ports",
        type=int,
        default=30,
        help="number of ports used for tracing (defaults to 30)",
    )

    if arg is not None:
        args = parser.parse_args(arg)
    else:
        args = parser.parse_args()

    ## start the program
    hosts = []

    if args.output is not None and not os.path.exists(args.output):
        CreateFolder(args)

    ## first off, we must get our list of hosts
    if args.hostnames is not None:
        ## host list
        hosts = args.hostnames
    elif args.file is not None:
        ## check file
        with open(args.file) as f:
            hosts = f.read().splitlines()
    elif args.har is not None:
        ## only open har, skip the rest
        print("Using pre-existing har")
        fullharname = args.har

    else:
        ## Error? Whould not happen?
        sys.exit("We have neither hosts nor file with hosts!")

    if args.har is not None:
        ## just put an empty placeholder here
        hostslist = [None]
    elif args.separate:
        # lists in list [[host1], [host2], etc]
        hostslist = list([i] for i in hosts)
    else:
        # list in list [[host1, host2, etc]]
        hostslist = [hosts]

    # Setup tracer
    if args.ports < 0:
        print("Cannot use negative number of ports, defaulting to 30")
        args.ports = 100

    # set nr of ports
    parallelltracert.TraceManager.SetPorts(args.ports)

    for hostset in hostslist:

        ## Prepare hosts
        with tempfile.TemporaryDirectory() as tmpdir:
            ## Check if we have har or should create it
            if args.har is None:
                ## We have to generate har file (i.e. we do not have them)
                fullharname = GenerateHarFile(hostset, tmpdir, args)

            ## Now we should have the harname, regardless of how we got it
            ## Lets analyze the har
            harchecker = harutilities.CheckHAR()
            harchecker.Load(fullharname)

            ## Prepare the har, i.e. resolve hosts, trace hosts and resolve
            ## ASNs (where possible)
            harchecker.cook()

            ## Do something more, or just close files and be happy?
            edges = harchecker.getEdges(useHostnames=True)

        ## create the graph
        with tempfile.NamedTemporaryFile() as tmpfile:
            chartname = tmpfile.name  # + ".png"
            files = internetgraph.draw_graph(edges, chartname)

            if args.output is not None:
                print("Copying graph-file to output")
                if Path(fullharname).stem == "run":
                    # make a better name from the current time
                    # HACK Do something smart out of the hosts we have
                    # which supports resolving the same host multiple
                    # times without name collision
                    now = datetime.now()
                    fmt = now.strftime("%Y%m%d_%H%M%S")
                    tochart = os.path.join(args.output, fmt)
                else:
                    # we have a decent name, hopefully
                    tochart = os.path.join(args.output, Path(fullharname).stem)

                for f in files:
                    copyfile(f, Path(tochart).with_suffix(f.suffix))

                # use (i.e. open) copied file instead
                # chartname will be opened in the end
                # use first
                chartname = Path(tochart).with_suffix(files[-1].suffix)

            if not args.quiet:
                print("Opening the graph (might take a while for big graphs)")
                import platform

                if platform.system() == "Darwin":
                    opencmd = "open {:}".format(chartname)
                elif platform.system() == "Linux":
                    opencmd = "xdg-open {:} &".format(chartname)
                else:  # Lets just run the file itself,
                    # works on some platforms (including Windows)
                    opencmd = "{:}".format(chartname)

                os.system(opencmd)


def CreateFolder(args):
    print("Creating output folder")
    os.makedirs(args.output)


def GenerateHarFile(hostset, tmpdir: str, args):
    ## Generates a har-file from a set of hosts
    with tempfile.NamedTemporaryFile() as tmpfile:

        hostset = list(urlutils.EnsureFullURI(h) for h in hostset)

        print("The set of hosts is {:}".format(hostset))

        ## need to generate a list of hosts for the chrome-har bash-script
        with open(tmpfile.name, "w+") as tf:
            hsnewlines = []
            ## write many
            for i in range(args.iterations):
                for hs in hostset:
                    hsnewlines.append(hs + "\n")

            tf.writelines(hsnewlines)

        ## We have prepared hosts, lets run
        harfilename, harfullname = CreateHarFile(tmpfile, tmpdir)

        ## load the actual har-file. This wil do work such as tracing
        if args.output is not None:
            print("Copying har-file to output")
            toharfile = os.path.join(args.output, harfilename)
            if len(hostset) == 1:
                # we have only one host, lets use smarter name
                uri = urlparse(hostset[0])
                toharfile = os.path.join(
                    args.output, uri.netloc.replace(".", "_") + ".har"
                )
                print(hostset)
                print("Moving har-file to {:}".format(toharfile))

            copyfile(harfullname, toharfile)
            #  change our reference so we used copied file instead
            harfullname = toharfile

        return harfullname


def CreateHarFile(tmpfile, tmpdir: str):
    ## We have prepared hosts, lets run
    subprocess.call(["./generatehar.sh", tmpfile.name, tmpdir])
    # subprocess.call(["ls", "-alh", tmpdir])

    ## Check that we only have one har-file
    files = list(filter(lambda x: ".har" in x, os.listdir(tmpdir)))
    if len(files) == 0:
        sys.exit("No har-file found. Did Chrome crash?")
    elif len(files) > 1:
        sys.exit("Multiple har-files found, something went wrong ({:})".format(files))

    # we should only have one
    harfilename = files[0]

    ## append to folder path
    harfullname = os.path.join(tmpdir, harfilename)
    return harfilename, harfullname


def is_root():
    return os.getuid() == 0


if __name__ == "__main__":

    if not is_root():
        # check for root and elevate
        print("Tracing will require root, trying to elevate")
        print("[If you do not trust this application, do not continue]")
        elevate(show_console=False, graphical=False)
        print("Elevated, restarting application as root")

    ## call main
    main()
else:
    # We are supposed to run as a script, for now just exit to avoid weird
    # behaviour.
    # change if needed
    sys.exit(2)
