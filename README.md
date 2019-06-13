# internet-tools
A collection of python tools useful in an Internet context.

In particular these functions are of interest:
- Managing headless chrome instance to model web-browsing.
- Parallel traceroute in python (as of now not compatible with Windows due to WinAPI issues)
- Graph / Network generator of networks captured with either the traceroute or the web-browser simulation

Depends heavily on other python modules and a contains a modified version of py-traceroute (https://github.com/dnaeon/pytraceroute).

## Installation instructions

First off, we need all dependencies

### Chrome-headless automation

This project is dependent on `chrome-har-capturer` (see https://github.com/cyrus-and/chrome-har-capturer) to captur hars with the help of Google Chrome / Chromium. 

Chrome or Chromium is easily installed by either your package manager or by googling a download link. As long as the version is relatively modern there should be no issues.

`chrome-har-capturer` is installed via npm like this:

    npm install chrome-har-capturer

If you are missing `npm` head over to https://nodejs.org/en/download/ and download and install `npm` / `nodejs`.

### Python dependencies

You also need som python modules, and of course python (3+) itself. Python is most easily downloaded from their homepage (https://www.python.org/downloads/) or your package manager of choice.

When you have pip(3) installed, run the following:

    pip3 install networkx matplotlib splinter bs4 cymruwhois pyasn dnspython

Depending on system pip3 might not be aliased and instead pip should be used. Also some systems might require pip3 to be run as root (or use the `--user` flag to do a user install).

## Using the tools

This repository contains tools usable in general python projects, such as (simple and task specific) har-parsing, parallellized UDP traceroute, and a tool for generating graphs of said traceroutes. 

### Modules

See `src/` directory, and in particular `tracert.py`, `har_wrapper.py` and `utils.py`. Depending on arguments it might be necessary to run `pyasn_util_download.py --latestv46` in the working directory for `pyasn` sake.

### Command line tools

The most interesting tool to use quickly is the `generate_map.py`, which generates a map / graph from either a list of urls or a set of har-files. Due to the nature of the traceroute (modifying packets at low level) root-acccess is required. On most systems this can be attained with `sudo`.

Some example usages:

    ## Visit Washington Post and show the graph afterwards (-w for website)
    sudo python3 generatemap.py -w www.nytimes.com www.cnn.com
    
    ## Draw a single graph based on a har (or set of hars) and puts the graphs in "myoutputfolder"
    sudo python3 generatemap.py -e inputfolder/some_data.har someotherfolder/some_data2.har -o myoutputfolder/
    
    ## Draw separate graphs based on urls quietly (-s or --separate to do individual runs, -q or --quiet for no output)
    sudo python3 generate_map.py -s -q washingtonpost.com nytimes.com cnn.com

