# Copyright (c) 2015 Marin Atanasov Nikolov <dnaeon@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer
#    in this position and unchanged.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Original code available at:
# https://github.com/dnaeon/pytraceroute
# Modified by adding parallellization and stamping out a few bugs.
# Available in modified form at:
# https://github.com/flindeberg/internet-tools

# TODO ipv6
# ipv6 does not work, feel free to fix it. 
# Issue is that the ipv6 packet when read as a buffer does not look as it 
# does on the wire (i.e. when captured by wireshark), so ICMPv6 packets
# don't have the required fields available.

"""
Core module

Currently only works on OSX, possibly some Linux-flavours, but not guaranteed
"""

import ipaddress
import os
import random
import socket
import struct
import sys
import threading
import time
## Use threads, not processes (processes are harder to coordinate for small tasks, also larger overhead)
from multiprocessing.pool import ThreadPool

__all__ = ['MyTracer']
__tracedebug__ = False

__MAXPORT__ = 33655
__MINPORT__ = 33434

def dprint(x):
    """
    Debug print for this module
    Prints if __tracedebug__ is set to true
    """
    if __tracedebug__:
        print(x)

## Class for "singletoning" the traces, often quite useful
class TraceManager(object):
    # Class specific variables
    __lock = threading.Condition()
    __traced = dict()
    __tracing = list()

    __d_noLookup = 0
    __d_Lookup = 0
    __d_tracing = 0

    __singleton = None

    ## 200 is arbitrarily chosen, seemed to work well on modern connections (i.e. ballpark gbit). Scale down if needed. 
    ## Lets use one per port we use instead
    __pool = ThreadPool(__MAXPORT__ - __MINPORT__ + 1)

    @classmethod
    def Instance(cls):
        # Gets the current instance

        cls.__lock.acquire()

        if not cls.__singleton:
            cls.__singleton = cls()

        cls.__lock.release()

        return cls.__singleton

    def __init__(self):
        if os.name == "nt":
            # TODO Add support for Windows? 
            raise Exception('Currently the implementation does not support Windows.')

        self.__sema = threading.RLock()
        

    @classmethod
    def TraceAll(cls, ips: list) -> dict:
        dprint ("in trace all")
        ins = cls.Instance()
        dprint ("got instance")
        results = dict()

        for i in ips:
            dprint("(MAIN) Starting {}".format(i))
            results[i] = cls.__pool.apply_async(ins.Trace,  (i,))
            #results.append(cls.__pool.apply_async(ins.Trace,  (i,)))

        dprint("(MAIN) Waiting for results")
        #results = list([r.get() for r in results])
        for key in ips:
            results[key] = results[key].get()
        dprint("(MAIN) Results fetched")

        print("(MAIN) We have traced {:} and have {:} tracing.".format(len(ins.__traced.keys()),len(ins.__tracing)))

        return results

    #@classmethod
    def Trace(self, ip: str):
        res = None
        local_ip = ip

        # Ensure only one thread is here at a time
        self.__sema.acquire()

        form = "Currently there are {:} traced and {:} tracing ({:}:{:}:{:}). Going for {:}"
        dprint (form.format(len(self.__traced.keys()), len(self.__tracing), self.__d_noLookup, self.__d_Lookup, self.__d_tracing, local_ip))

        if local_ip in self.__traced.keys():
            # Its already traces, lets assume its correct
            self.__d_noLookup += 1
            res = self.__traced[local_ip]
        elif local_ip in self.__tracing:
            # Its currently being traced
            self.__sema.release()
            dprint ("Waiting for {:}".format(local_ip))
            # We can wait here a bit, noone will die
            # remember that we are waiting for a network, i.e. slow.
            time.sleep(0.5)
            return self.Trace(local_ip)
        else:
            # A new host!
            self.__d_tracing += 1
            self.__d_Lookup += 1
            self.__tracing.append(local_ip)
            self.__sema.release()
            # release lock since host is set as "being traced"
            # trace
            # use tracer onece, and then kill
            ips = MyTracer(local_ip, hops=30, quiet=True).trun()

            self.__sema.acquire()
            # get the lock back and add to traced
            self.__traced[local_ip] = ips
            self.__tracing.remove(local_ip)
            self.__d_tracing -= 1
            res = ips

        self.__sema.release()

        form = "Traced {:} ({:}/{:}, {:}%, {:} ongoing)"
        print (form.format(
            local_ip, 
            len(self.__traced.keys()), 
            (len(self.__tracing) + len(self.__traced.keys())),
            round(100 * (len(self.__traced.keys())) / (len(self.__tracing) + len(self.__traced.keys())),2),
            len(self.__tracing)
        ))

        return res
            
class Query(object):
    
    def __init__(self, port):
        self.port = port
        self.hops = list()
        # init with empty sema
        self.sema = threading.Semaphore(0)
        self.startTimer = None
        self.lock = threading.Lock()

class Hop(object):

    def __init__(self, addr, rtt):
        self.rtt = rtt
        self.addr = addr

class MyTracer(object):

    # class based lock, used for syncing with the listener which is class based.
    lock = threading.Lock()
    # the set of used ports (dst-port, not the port we send from!
    # due to the way ICMP works we need a unique dst-port for all traces
    ports = set()
    # a dict filled with running queries
    runningQueries = dict()

    # class based semaphore for signaling that the listener can start listening
    recieveSema = threading.Semaphore(0)

    # for keeping track of whether our listener is running or not
    listening = False

    timeoutSec = 1

    def __init__(self, dst, hops=30, quiet=False):
        """
        Initializes a new tracer object
        Args:
            dst  (str): Destination host to probe
            hops (int): Max number of hops to probe
        """
        self.dst = dst
        self.hops = hops
        self.ttl = 1

        # ensure that we have a unique port
        self.setPort()

        # Should we be quiet or not?
        self.quiet = quiet

        # Loop for starting the listener
        with MyTracer.lock:
            if not MyTracer.listening:
                # important to use a THREADpool, and not a pool which is processes
                # we don't want processes, period. Processes in Python are weird. 
                pool = ThreadPool(1)
                # start it
                pool.apply_async(MyTracer.listen)
                # set listening to true and then release the lock
                MyTracer.listening = True


    def setPort(self):
        while True:
            with MyTracer.lock:
                # Pick up a random port in the range 33434-33534
                #self.port = random.choice(range(33434, 33464))
                self.port = random.choice(range(__MINPORT__, __MAXPORT__))
                
                if self.port not in MyTracer.ports:
                    MyTracer.ports.add(self.port)
                    return

    @classmethod
    def listen(cls):
        """ 
        Method for starting a class-based listener
        
        Note: Class-method, not instance-method, serves all instances
        """
        try:
            # Create a reusable reviever
            # We will use this throughout the lifecycle
            print ("(listener) Starting")
            r4, r6 = cls.create_receiver()

            while True:
            
                localport = None
                addr = None

                # Get the sema, then try to recieve
                # Ergo we wait here untill a sending thread signals that we should wait for something
                cls.recieveSema.acquire()

                try:
                    # Read from socket. Will timeout based on socket settings.
                    # Timeout will raise socket.error
                    # We don't care about big packets. They are prolly not coming from us anyhow
                    data, addr = r4.recvfrom(1024)
                    
                    # Check that it is an ICMP package and its a 3 / 3 or 11 / 0
                    #  i.e.
                    # destination uncreachable / port unreachable
                    # or 
                    # ttl exceeded / ttl exceeded in traffic
                    # see https://tools.ietf.org/html/rfc792 for details
                    # That means (in an IP-packet sense) it has to be either
                    # byte  9 == 1 (ICMP)
                    # byte 20 == 3 (destination unreachable)
                    # byte 21 == 3 (port unreachable)
                    # or 
                    # byte  9 ==  1 (ICMP)
                    # byte 20 == 11 (time-to-live exceeded)
                    # byte 21 ==  0 (ttl exceeded in traffic)
                    if not data[9] == 1:
                        # Not ICMP, don't really know what to do here, skip it?
                        # lets skip it
                        continue
                    elif not (data[20] == 11 and data[21] == 0) \
                        and not (data[20] == 3 and data[21] == 0) \
                        and not (data[20] == 3 and data[21] == 3) \
                        and not (data[20] == 3 and data[21] == 10) \
                        and not (data[20] == 3 and data[21] == 13):
                        # ICMP which is not 3/3-10-13 or 11/0
                        continue

                    # Here we know its ICMP *and* useful

                    # Get the port from the data
                    # Normally the port for the request will be in 
                    # position 50+51 (if only counting IP-packet bytes) 
                    # or position 64+65 if counting the entire eth-frame
                    # we reduce dependencies by only looking at the ip-frame
                    # as a buffer of bytes rather than importing packages for 
                    # parsing IP-packets and ETH-frames
                    localport = data[50]*256+data[51]    
                    endTimer = time.time()
                    # get the host from addr (i.e. addr[0], addr[1] is port which is 0 for ICMP)
                    addr = addr[0]

                except socket.error as e:
                    ### We should try IPv6, but it doesn't work!
                    ### IPv6 disabled at send for now
                    try:
                        # Jump to wait for next packet
                        # We probably didn't recieve anything and won't do it later
                        #print ("Got socketerror {:}".format(e))
                        # Read from socket. Will timeout based on socket settings.
                        # Timeout will raise socket.error
                        # We don't care about big packets. They are prolly not coming from us anyhow
                        data, addr = r6.recvfrom(1024)
                        
                        # Check that it is an ICMP package and its a 3 / 3 or 11 / 0
                        #  i.e.
                        # destination uncreachable / port unreachable
                        # or 
                        # ttl exceeded / ttl exceeded in traffic
                        # see https://tools.ietf.org/html/rfc4443 for details
                        # That means (in an IP-packet sense) it has to be either
                        # byte  8 == 58 (ICMPv6)
                        # byte 40 ==  3 (destination unreachable)
                        # byte 41 ==  3 (port unreachable)
                        # or 
                        # byte  8 == 58 (ICMPv6)
                        # byte 40 == 11 (time-to-live exceeded)
                        # byte 41 ==  0 (ttl exceeded in traffic)
                        if not data[8] == 58: 
                            # Not ICMP, don't really know what to do here, skip it?
                            # lets skip it
                            continue
                        elif not (data[40] == 3 and data[41] == 0) \
                            and not (data[40] == 3 and data[41] == 1) \
                            and not (data[40] == 1):
                            # ICMP which is not 3/3-10-13 or 11/0
                            continue

                        # Here we know its ICMP *and* useful

                        # Get the port from the data
                        # Normally the port for the request will be in 
                        # position 50+51 (if only counting IP-packet bytes) 
                        # or position 64+65 if counting the entire eth-frame
                        # we reduce dependencies by only looking at the ip-frame
                        # as a buffer of bytes rather than importing packages for 
                        # parsing IP-packets and ETH-frames
                        # moved for icmpv6 (+40)
                        localport = data[90]*256+data[91]    
                        endTimer = time.time()
                        # get the host from addr (i.e. addr[0], addr[1] is port which is 0 for ICMP)
                        addr = addr[0]

                    except socket.error as e2:
                        dprint ("listener got socket.error: {:}".format(e2))
                        continue

                if localport not in cls.runningQueries.keys():
                    # There is no key, so they thought we timed out because we were slow.
                    # just skip it, the other thread is no longer waiting
                    continue

                # Get the running query
                query = cls.runningQueries[localport]

                with query.lock:
                    # Just for the heck of it we lock on the query lock
                    # Easier for refactoring then since it is possible to do
                    # things from other threads
                    timeCost = round((endTimer - query.startTimer) * 1000, 2)

                    # store the hops we've made
                    query.hops.append(Hop(addr, timeCost))
                    
                # signal the waiting sender thread to continue
                query.sema.release()

        # all of these mean that the listener has crashed!
        # should really be taken care of somewhere, but I aint got time for that!
        except AttributeError as ae:
            # happens a lot during refactor (pylint has some issues?)
            print ("listener got AttributeError {:}".format(ae))
        except KeyError as ke:
            # probably due to accessing wrong key in the dict
            print ("listener got KeyError: {:}".format(ke))
        except PermissionError as pe:
            print ("Permission error, we cannot trace, re raising")
            raise pe
        except:
            # should not happen any more
            print ("Unexpected error in listener: {:}".format(sys.exc_info()[0]))
        finally:
            # So, the litener has crashed, lets set it as off so the next instance of the
            # class will start a new one.
            print ("(listener) Closing down the listener due to error!")

            # Does not support windows for now
            #if os.name == "nt":
                # We have windows. Can't get it to work though
            #    receiver.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

            cls.listening = False
            
    def trun(self) -> list:
        """
        Run the tracer with threads
        Raises:
            IOError
        """

        try:
            # start with checking if we have an ip (works with ipv4 and ipv6)
            ip_inner = ipaddress.ip_address(self.dst)
            dst_ip = ip_inner
        except Exception as e:
            # resolve hostname to IP
            # does not handle ipv6 (socket.gethostbyname)
            try:
                ip_inner = ipaddress.ip_address(socket.gethostbyname(self.dst))
                dst_ip = ip_inner
            except socket.error as e:
                raise IOError('Unable to resolve {}: {}', self.dst, e)

        # print something to output if we want to
        text = 'traceroute to {} ({}), {} hops max'.format(
            self.dst,
            dst_ip.exploded,
            self.hops
        )
        if not self.quiet:
            print(text)

        # creaty the query object we will but in the running queries
        # dictionary. Using the class based lock
        myQuery = Query(self.port)
        with MyTracer.lock:
            MyTracer.runningQueries[self.port] = myQuery

        while True:
            myQuery.startTimer = time.time()
            sender = self.create_sender(dst_ip)

            if not self.quiet:
                print ("sending to {:} with ttl {:}".format(self.dst, self.ttl))

            try:
                sender.sendto(b'', (dst_ip.compressed, self.port))
            except Exception as e:
                print("MyTrace Error with {:},{:}".format(dst_ip.exploded, self.port))
                print(e)
                raise IOError('MyTrace Unable to send {}: {}', dst_ip.compressed, e)

            # signal that something is ready
            MyTracer.recieveSema.release()
            # wait for the result
            if not myQuery.sema.acquire(timeout=MyTracer.timeoutSec):
                # we did not get a response
                with myQuery.lock:
                    myQuery.hops.append(Hop("*", None))
            else:
                # we got a nice response, lets use it
                # get the last hop
                lastHop = myQuery.hops[-1]
            
                if lastHop.addr:
                    timeCost = lastHop.rtt

                    # Only print shit if we really need it
                    if not self.quiet:
                        print('{:<4} {} {} ms'.format(self.ttl, lastHop.addr, timeCost))

                    if lastHop.addr == self.dst:
                        break
                    
                    if lastHop.addr == dst_ip:
                        break
                else:
                    if not self.quiet:
                        print('{:<4} *'.format(self.ttl))

            self.ttl += 1

            if self.ttl > self.hops:
                # we have gone to far, abort!
                break

        with MyTracer.lock:
            # Clean up our used port, both from the set and our collection of ongoing queries
            try:
                del MyTracer.runningQueries[self.port]
                MyTracer.ports.remove(self.port)
            except:
                print ("Got unknown error when cleaning up")
            

        # End with returning the hops
        # for now we enumerate a list with the addresses. 
        # Maybe might be interesting for some to return the rtt as well?
        return list([x.addr for x in myQuery.hops])

    @classmethod
    def create_receiver(cls):
        """
        Creates a receiver socket
        Returns:
            Two socket instances, one for ipv4 (icmp) and one for ipv6 (icmp6)
        Raises:
            IOError
        """

        s4 = socket.socket(
            family=socket.AF_INET,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMP
        )

        timeout = struct.pack("ll", MyTracer.timeoutSec, 0)
        s4.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

        try:
            # We are not binding a port, recieving ICMP, i.e. neither TCP nor UDP, ergo no port
            s4.bind(('', 0))
        except socket.error as e:
            raise IOError('Unable to bind receiver socket: {}'.format(e))

        # If we are windows, promiscious mode on
        # Does not work, we fail earlier for windows
        #if os.name == "nt":
        #    s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

        s6 = socket.socket(
            family=socket.AF_INET6,
            type=socket.SOCK_RAW,
            proto=socket.IPPROTO_ICMPV6
        )

        timeout = struct.pack("ll", MyTracer.timeoutSec, 0)
        s6.setsockopt(socket.SOL_SOCKET, socket.SO_RCVTIMEO, timeout)

        try:
            # We are not binding a port, recieving ICMP, i.e. neither TCP nor UDP, ergo no port
            s6.bind(('', 0))
        except socket.error as e:
            raise IOError('Unable to bind receiver socket: {}'.format(e))

        return s4, s6

    def create_sender(self, ipvx):
        """
        Creates a sender socket
        Returns:
            A socket instance
        """
        if isinstance(ipvx, ipaddress.IPv4Address):
            s = socket.socket(
                family=socket.AF_INET,
                type=socket.SOCK_DGRAM,
                proto=socket.IPPROTO_UDP
            )
            s.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
        elif isinstance(ipvx, ipaddress.IPv6Address):
            s = socket.socket(
                family=socket.AF_INET6,
                type=socket.SOCK_DGRAM,
                proto=socket.IPPROTO_UDP
            )
            s.setsockopt(socket.IPPROTO_IPV6, socket.IP_TTL, self.ttl)
        else:
            raise Exception("Unknown IP type! {:}, {:}".format(ipvx, type(ipvx)))

        return s


if __name__ == "__main__":
    # We are running this one, lets run 
    # just something for the heck of it
    num_cores = 64
    listargs = ["8.8.8.8", "8.8.4.4", "www.washingtonpost.com", "www.dn.se", "8.8.8.8", "www.dn.se", "8.8.8.8", "8.8.4.4"]
    
    print (os.name)
    results = TraceManager.TraceAll(listargs)

    print("(MAIN) Results gotten")

    for h,r in zip(listargs,results):
        print ("(MAIN) One trace:({:})".format(h))
        print (r)
