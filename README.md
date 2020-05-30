# internet-tools
A collection of python tools useful in an Internet context.

In particular these functions are of interest:
- Managing headless chrome instance to model web-browsing.
- Parallel traceroute in python (as of now not compatible with Windows due to WinAPI issues)
- Graph / Network generator of networks captured with either the traceroute or the web-browser simulation

Depends heavily on other python modules and a contains a modified version of py-traceroute (https://github.com/dnaeon/pytraceroute).

And a word of warning, this repository exists to show code used in my thesis, not primarily so others can reuse this. The code quality as awful, use at your own risk :-)

## Installation instructions

First off, we need all dependencies

### Chrome-headless automation

This project is dependent on `chrome-har-capturer` (see https://github.com/cyrus-and/chrome-har-capturer) to capture hars with the help of Google Chrome / Chromium. 

Chrome or Chromium is easily installed by either your package manager or by googling a download link. As long as the version is relatively modern there should be no issues.

`chrome-har-capturer` is installed via npm like this (`--global` is needed for the utility to be on `path`):

    npm install --global chrome-har-capturer

If you are missing `npm` head over to https://nodejs.org/en/download/ and download and install `npm` / `nodejs`.

### Graphviz (partially optional)

Graphviz is the most decent graph generator I have found, as such I really suggest it. Graphviz is available on most linux distributions and in `brew` for OSX.

### Python dependencies

You also need som python modules, and of course python (3+) itself. Python is most easily downloaded from their homepage (https://www.python.org/downloads/) or your package manager of choice.

When you have pip(3) installed, run the following:

    pip3 install networkx matplotlib splinter bs4 pyasn dnspython pycountry elevate string-grouper cleanco pygraphviz

Depending on system pip3 might not be aliased and instead pip should be used. Also some systems might require pip3 to be run as root (or use the `--user` flag to do a user install).

## Using the tools

This repository contains tools usable in general python projects, such as (simple and task specific) har-parsing, parallellized UDP traceroute, and a tool for generating graphs of said traceroutes. 

### Modules

See `src/` directory, and in particular `generatemap.py`, `parallelltracert.py`, `harutilities.py` and `internetgraph.py`. The har generation is done by `generatehar.sh`, a bash-script, which handles input / output and invokes `chrome-har-capturer` with decent arguments (i.e. timeouts). 

### Command line tools

The most interesting tool to use quickly is the `generate_map.py`, which generates a map / graph from either a list of urls or a set of har-files. Due to the nature of the traceroute (modifying packets at low level) root-acccess is required. On most systems this can be attained with `sudo`. This meanst that *you* should make sure that you understand what the Python-script does before running it).

Some example usages:

    ## Generatemap will always ask for priv-escalation unless found

    ## Visit New York Times and CNN, and then show the graph (-w for website)
    python3 generatemap.py -w www.nytimes.com www.cnn.com
    
    ## Draw a single graph based on a har (or set of hars) and put the graphs in "myoutputfolder"
    python3 generatemap.py -e inputfolder/some_data.har someotherfolder/some_data2.har -o myoutputfolder/
    
    ## Draw separate graphs based on urls quietly (-s or --separate to do individual runs, -q or --quiet for no output)
    python3 generatemap.py -s -q -w thesun.co.uk nytimes.com cnn.com -o testingsep
    

