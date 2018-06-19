# internet-tools
A collection of python tools useful in an Internet context.

In particular these functions are of interest:
- Managing headless chrome instance to model web-browsing.
- Parallel traceroute in python (as of now not compatible with Windows due to WinAPI issues)
- Graph / Network generator of networks captured with either the traceroute or the web-browser simulation

Depends heavily on other python modules and a contains a modified version of py-traceroute (https://github.com/dnaeon/pytraceroute).