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

"""
Core module

Works on OSX and Linux (not Windows), for both IPv4 and IPv6. On Linux and
macOS tracing needs no elevated privileges (see UnprivilegedTracer and
_macos_unprivileged_available below); elsewhere it needs root for raw ICMP
sockets (see RawSocketTracer).
"""

import functools
import ipaddress
import os
import random
import select
import socket
import struct
import sys
import threading
import time

## Use threads, not processes (processes are harder to coordinate for small tasks, also larger overhead)
from multiprocessing.pool import ThreadPool

__all__ = ["TraceManager"]
__tracedebug__ = False  ## HACK for debug prints

## HACK empirically the cutoff seems to be around 33634
## standardswise this should not be an issue
__MAXPORT__ = 33464
# __MAXPORT__ = 33634
__MINPORT__ = 33434

## Stop a trace after this many hops in a row without an answer, the rest is
## most likely filtered as well (same default as e.g. scamper's gap limit).
## Saves up to (hops - gap limit) * timeout seconds per filtered destination.
__GAPLIMIT__ = 5

## ICMP(v6) types answering a UDP probe: destination unreachable (we reached
## the target, or a router gave up) and time exceeded (ttl ran out at a router)
## See https://tools.ietf.org/html/rfc792 and https://tools.ietf.org/html/rfc4443
_ICMP4_ERROR_TYPES = (3, 11)
_ICMP6_ERROR_TYPES = (1, 3)


def dprint(x):
    """
    Debug print for this module
    Prints if __tracedebug__ is set to true
    """
    if __tracedebug__:
        print(x)


## Linux socket options for reading ICMP errors off a socket's error queue.
## Python does not expose all of them (e.g. not IP_RECVERR before 3.14), but
## they are part of the Linux ABI, the same on all architectures
## (linux/in.h, linux/in6.h, linux/socket.h)
_IP_RECVERR = getattr(socket, "IP_RECVERR", 11)
_IPV6_RECVERR = getattr(socket, "IPV6_RECVERR", 25)
_MSG_ERRQUEUE = getattr(socket, "MSG_ERRQUEUE", 0x2000)


def _linux_unprivileged_available() -> bool:
    """
    Whether we can trace without raw sockets (and therefore without root) on
    this platform, using IP_RECVERR/IPV6_RECVERR + MSG_ERRQUEUE to read ICMP
    errors off a plain UDP socket's error queue.

    This is a Linux-only kernel/socket-API feature, see
    _macos_unprivileged_available for macOS.
    """
    return sys.platform.startswith("linux")


@functools.lru_cache(maxsize=None)
def _macos_unprivileged_available() -> bool:
    """
    Whether RawSocketTracer can listen without root, using ICMP sockets of
    type SOCK_DGRAM instead of SOCK_RAW.

    macOS lets unprivileged users open such sockets (it is what ping uses),
    and unlike Linux' "ping sockets" they also receive the ICMP(v6) errors
    caused by our UDP probes. What they receive has the same layout as from
    a raw socket (IPv4 including the IP header, ICMPv6 without), so the
    listener works unchanged.
    """
    if sys.platform != "darwin":
        return False
    try:
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP).close()
        return True
    except OSError:
        return False


def requires_root() -> bool:
    """Whether tracing on this platform needs raw sockets, and therefore root."""
    return not (_linux_unprivileged_available() or _macos_unprivileged_available())


def create_tracer(dst, hops=30, quiet=False):
    """Factory picking the best tracer implementation for this platform."""
    if _linux_unprivileged_available():
        return UnprivilegedTracer(dst, hops=hops, quiet=quiet)
    return RawSocketTracer(dst, hops=hops, quiet=quiet)


def _resolve(dst):
    """Returns dst as an ipaddress object, resolving it if it is a hostname"""
    try:
        return ipaddress.ip_address(dst)
    except ValueError:
        # does not handle ipv6 (socket.gethostbyname)
        try:
            return ipaddress.ip_address(socket.gethostbyname(dst))
        except socket.error as e:
            raise IOError("Unable to resolve {}: {}".format(dst, e))


def _trace_hops(dst_ip, hops: int, quiet: bool, probe) -> list:
    """
    Probes ttl 1, 2, ... in turn until the destination answers, we reach
    hops, or __GAPLIMIT__ hops in a row have not answered.
    probe(ttl) returns (addr, rtt_ms) of whoever answered, or (None, None).
    Returns:
        list of hop addresses (str), "*" for hops that did not answer
    """
    hopAddrs = []
    gap = 0
    for ttl in range(1, hops + 1):
        addr, rtt = probe(ttl)

        if addr:
            gap = 0
            if not quiet:
                print("{:<4} {} {} ms".format(ttl, addr, rtt))
            hopAddrs.append(addr)
            if ipaddress.ip_address(addr) == dst_ip:
                break
        else:
            gap += 1
            if not quiet:
                print("{:<4} *".format(ttl))
            hopAddrs.append("*")
            if gap >= __GAPLIMIT__:
                break

    return hopAddrs


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

    ## Lets use one per port, works good enough
    __pool: ThreadPool = None

    @classmethod
    def SetPorts(cls, ports: int):
        global __MAXPORT__
        __MAXPORT__ = __MINPORT__ + ports - 1
        cls.__pool = ThreadPool(ports)

    @classmethod
    def Instance(cls):
        # Gets the current instance

        cls.__lock.acquire()

        if not cls.__singleton:
            cls.__singleton = cls()
            # keep the pool if SetPorts has already made one
            if cls.__pool is None:
                cls.__pool = ThreadPool(__MAXPORT__ - __MINPORT__ + 1)

        cls.__lock.release()

        return cls.__singleton

    def __init__(self):
        if os.name == "nt":
            # TODO Add support for Windows?
            raise Exception("Currently the implementation does not support Windows.")

        self.__sema = threading.RLock()

    @classmethod
    def TraceAll(cls, ips: list) -> dict:
        dprint("in trace all")
        ins = cls.Instance()
        dprint("got instance")
        pending = dict()

        # each ip once, duplicates would only wait for the same trace anyway
        for i in set(ips):
            dprint("(MAIN) Starting {}".format(i))
            pending[i] = cls.__pool.apply_async(ins.Trace, (i,))

        dprint("(MAIN) Waiting for results")
        results = {key: res.get() for key, res in pending.items()}
        dprint("(MAIN) Results fetched")

        print(
            "(MAIN) We have traced {:} and have {:} tracing.".format(
                len(ins.__traced.keys()), len(ins.__tracing)
            )
        )

        return results

    # @classmethod
    def Trace(self, ip: str):
        res = None
        local_ip = ip

        # Ensure only one thread is here at a time
        self.__sema.acquire()

        form = "Currently there are {:} traced and {:} tracing ({:}:{:}:{:}). Going for {:}"
        dprint(
            form.format(
                len(self.__traced.keys()),
                len(self.__tracing),
                self.__d_noLookup,
                self.__d_Lookup,
                self.__d_tracing,
                local_ip,
            )
        )

        if local_ip in self.__traced.keys():
            # Its already traces, lets assume its correct
            self.__d_noLookup += 1
            res = self.__traced[local_ip]
        elif local_ip in self.__tracing:
            # Its currently being traced
            self.__sema.release()
            dprint("Waiting for {:}".format(local_ip))
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
            ips = create_tracer(local_ip, hops=30, quiet=True).trun()

            self.__sema.acquire()
            # get the lock back and add to traced
            self.__traced[local_ip] = ips
            self.__tracing.remove(local_ip)
            self.__d_tracing -= 1
            res = ips

        self.__sema.release()

        form = "Traced {:} ({:}/{:}, {:}%, {:} ongoing), ports {:}-{:}"
        print(
            form.format(
                local_ip,
                len(self.__traced.keys()),
                (len(self.__tracing) + len(self.__traced.keys())),
                round(
                    100
                    * (len(self.__traced.keys()))
                    / (len(self.__tracing) + len(self.__traced.keys())),
                    2,
                ),
                len(self.__tracing),
                __MINPORT__,
                __MAXPORT__,
            )
        )

        return res


class Query(object):
    def __init__(self, port, srcport):
        self.port = port
        # source port of all probes of this trace
        self.srcport = srcport
        # the probe currently waiting for an answer, identified by its UDP length
        self.udplen = None
        self.reply = None
        self.sema = threading.Semaphore(0)
        self.startTimer = None
        self.lock = threading.Lock()


class Hop(object):
    def __init__(self, addr, rtt):
        self.rtt = rtt
        self.addr = addr


# struct sock_extended_err (linux/errqueue.h) origin values we care about,
# i.e. the error actually came back from the network as an ICMP(v6) message
# (as opposed to e.g. SO_EE_ORIGIN_LOCAL, a locally-generated error).
_SO_EE_ORIGIN_ICMP = 2
_SO_EE_ORIGIN_ICMP6 = 3


class UnprivilegedTracer(object):
    """
    UDP traceroute using IP_RECVERR/IPV6_RECVERR (Linux only), needing no raw
    sockets and therefore no root.

    Each probe sends from its own regular UDP socket with IP(V6)_RECVERR
    enabled; the kernel then queues any resulting ICMP error (time exceeded,
    or port/destination unreachable once we reach the target) on that same
    socket's error queue, retrievable via recvmsg(..., MSG_ERRQUEUE). Because
    each probe gets its answer back on its own socket, there is no need for
    RawSocketTracer's shared listener thread / destination-port demuxing.

    All probes of a trace are sent from the same source port, so that they
    are one flow to load balancing (ECMP) routers and follow the same path
    (as in Paris traceroute). Otherwise each probe may take a different
    path, giving duplicate or missing hops.
    """

    timeoutSec = 1

    def __init__(self, dst, hops=30, quiet=False):
        self.dst = dst
        self.hops = hops
        self.quiet = quiet

    def trun(self) -> list:
        """
        Runs the tracer.
        Raises:
            IOError
        """
        dst_ip = _resolve(self.dst)

        if not self.quiet:
            print(
                "traceroute to {} ({}), {} hops max".format(
                    self.dst, dst_ip.exploded, self.hops
                )
            )

        # dst-port only needs to be unique enough not to collide with a
        # "real" listening service; unlike RawSocketTracer we don't need it
        # to demux answers (each probe's own socket does that for us).
        port = random.randint(__MINPORT__, __MAXPORT__)

        # source port, picked by the OS for the first probe and reused after that
        self.srcport = 0

        return _trace_hops(
            dst_ip, self.hops, self.quiet, lambda ttl: self._probe(dst_ip, port, ttl)
        )

    def _bind(self, s, family):
        """Binds s to this trace's source port (if we have one yet)"""
        anyaddr = "0.0.0.0" if family == socket.AF_INET else "::"
        try:
            s.bind((anyaddr, self.srcport))
        except OSError:
            # someone else took the port in between our probes, rather a
            # new flow than no trace at all
            s.bind((anyaddr, 0))
        self.srcport = s.getsockname()[1]

    def _probe(self, dst_ip, port, ttl):
        """
        Sends a single UDP probe at the given ttl/hop-limit and waits for the
        resulting ICMP error on the probe socket's own error queue.
        Returns:
            (addr, rtt_ms) of the router/host that answered, or (None, None)
            on timeout.
        """
        if isinstance(dst_ip, ipaddress.IPv4Address):
            family = socket.AF_INET
            level = socket.SOL_IP
            recverr_opt = _IP_RECVERR
            ttl_opt = socket.IP_TTL
            origin = _SO_EE_ORIGIN_ICMP
        else:
            family = socket.AF_INET6
            level = socket.IPPROTO_IPV6
            recverr_opt = _IPV6_RECVERR
            ttl_opt = socket.IPV6_UNICAST_HOPS
            origin = _SO_EE_ORIGIN_ICMP6

        s = socket.socket(family, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            s.setsockopt(level, recverr_opt, 1)
            s.setsockopt(level, ttl_opt, ttl)
            s.settimeout(self.timeoutSec)
            self._bind(s, family)

            start = time.time()
            try:
                # payload length tells this probe apart from the earlier ones
                # of the trace (same flow, so same socket for late errors)
                s.sendto(b"\0" * ttl, (dst_ip.compressed, port))
            except OSError as e:
                # some errors (e.g. immediate "no route") can be raised
                # synchronously here rather than via the error queue
                dprint("send error at ttl {:}: {:}".format(ttl, e))
                return None, None

            while True:
                remaining = start + self.timeoutSec - time.time()
                if remaining <= 0:
                    return None, None
                s.settimeout(remaining)

                try:
                    data, ancdata, _flags, _addr = s.recvmsg(512, 1024, _MSG_ERRQUEUE)
                except (socket.timeout, OSError):
                    return None, None

                # the error queue gives us the payload quoted in the ICMP error,
                # which is empty if the router only quoted the UDP header
                if len(data) not in (0, ttl):
                    # late answer to an earlier probe, keep waiting for ours
                    continue

                rtt = round((time.time() - start) * 1000, 2)

                for cmsg_level, cmsg_type, cmsg_data in ancdata:
                    if cmsg_level == level and cmsg_type == recverr_opt:
                        addr = self._parse_offender(family, origin, cmsg_data)
                        if addr:
                            return addr, rtt
        finally:
            s.close()

    @staticmethod
    def _parse_offender(family, expected_origin, cmsg_data):
        """
        Parses the ancillary data delivered alongside IP(V6)_RECVERR: a
        struct sock_extended_err (linux/errqueue.h) immediately followed by
        the offending router/host's address as a sockaddr. Returns the
        address as a string, or None if this isn't a real network-origin
        ICMP error (or the offender is missing/malformed).
        """
        # struct sock_extended_err {
        #     __u32 ee_errno; __u8 ee_origin; __u8 ee_type;
        #     __u8 ee_code; __u8 ee_pad; __u32 ee_info; __u32 ee_data;
        # };
        if len(cmsg_data) <= 16:
            return None

        _errno, ee_origin, _type, _code, _pad, _info, _data = struct.unpack_from(
            "=IBBBBII", cmsg_data, 0
        )

        if ee_origin != expected_origin:
            # e.g. SO_EE_ORIGIN_LOCAL: a locally generated error, not a hop
            return None

        offender = cmsg_data[16:]

        try:
            if family == socket.AF_INET:
                # struct sockaddr_in { u16 family; u16 port; u8 addr[4]; ... }
                if len(offender) < 8:
                    return None
                return socket.inet_ntop(socket.AF_INET, offender[4:8])
            else:
                # struct sockaddr_in6 { u16 family; u16 port;
                #                       u32 flowinfo; u8 addr[16]; u32 scope_id; }
                if len(offender) < 24:
                    return None
                return socket.inet_ntop(socket.AF_INET6, offender[8:24])
        except (struct.error, OSError, ValueError):
            return None


class RawSocketTracer(object):
    """
    UDP traceroute where one shared listener thread reads the ICMP(v6)
    errors for all running traces. An error is matched to its trace by the
    UDP destination port quoted in it (unique per trace), and to its probe
    by the quoted UDP length (payload length = ttl), so a late answer to a
    probe that has already timed out is not mistaken for the next hop.

    All probes of a trace are sent from one socket, i.e. the same source
    port, so that they are one flow to load balancing (ECMP) routers and
    follow the same path (as in Paris traceroute). Otherwise each probe may
    take a different path, giving duplicate or missing hops.

    The listener needs raw ICMP sockets (i.e. root), except on macOS where
    ICMP datagram sockets work as well (see _macos_unprivileged_available).
    """

    # class based lock, used for syncing with the listener which is class based.
    lock = threading.Lock()
    # the set of used ports (dst-port, not the port we send from!
    # due to the way ICMP works we need a unique dst-port for all traces
    ports = set()
    # a dict filled with running queries
    runningQueries = dict()

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

        # Should we be quiet or not?
        self.quiet = quiet

        # Start the listener if it is not running. Its sockets are created
        # here rather than in the listener thread, so that a failure (e.g. a
        # PermissionError without root) reaches the caller
        with RawSocketTracer.lock:
            if not RawSocketTracer.listening:
                receivers = RawSocketTracer.create_receivers()
                threading.Thread(
                    target=RawSocketTracer.listen,
                    args=(receivers,),
                    name="tracer-listener",
                    daemon=True,
                ).start()
                RawSocketTracer.listening = True

        # ensure that we have a unique port
        self.setPort()

    def setPort(self):
        while True:
            with RawSocketTracer.lock:
                # Pick up a random port in the range
                self.port = random.choice(range(__MINPORT__, __MAXPORT__ + 1))

                if self.port not in RawSocketTracer.ports:
                    RawSocketTracer.ports.add(self.port)
                    return

            # Sleep to avoid cpu thrashing
            time.sleep(0.01)

    @staticmethod
    def parse_icmp4(data: bytes):
        """
        Parses what an IPv4 ICMP socket received: the IPv4 header, the ICMP
        header, and the start of the packet that caused the error (IPv4
        header + UDP header).
        Returns:
            (source port, destination port, length) from the header of the
            UDP packet that caused the error, or None if this is not an
            answer to a UDP probe
        """
        if len(data) < 20 or data[9] != socket.IPPROTO_ICMP:
            return None
        # header lengths are in 32-bit words, more than 20 bytes with options
        ihl = (data[0] & 0x0F) * 4
        inner = ihl + 8
        if len(data) < inner + 20 or data[ihl] not in _ICMP4_ERROR_TYPES:
            return None
        udp = inner + (data[inner] & 0x0F) * 4
        # every ICMP error quotes at least the 8-byte UDP header (RFC 792)
        if data[inner + 9] != socket.IPPROTO_UDP or len(data) < udp + 8:
            return None
        return struct.unpack_from("!HHH", data, udp)

    @staticmethod
    def parse_icmp6(data: bytes):
        """
        Same as parse_icmp4, for ICMPv6.

        Note: unlike IPv4, raw (and datagram) ICMPv6 sockets never include
        the outer IPv6 header on receive (a deliberate difference in the
        IPv6 socket API, see RFC 3542), so data starts directly with the
        8-byte ICMPv6 header, followed by the packet that caused the error
        (40-byte IPv6 header + UDP header).
        """
        udp = 8 + 40
        if len(data) < udp + 8 or data[0] not in _ICMP6_ERROR_TYPES:
            return None
        # next header of the inner IPv6 header (our probes have no extension headers)
        if data[8 + 6] != socket.IPPROTO_UDP:
            return None
        return struct.unpack_from("!HHH", data, udp)

    @classmethod
    def listen(cls, receivers: dict):
        """
        Method for running the class-based listener, reading ICMP(v6) errors
        and handing each to the probe waiting for it

        Note: Class-method, not instance-method, serves all instances
        """
        try:
            print("(listener) Starting")

            while True:
                ready, _, _ = select.select(list(receivers), [], [])

                for sock in ready:
                    # We don't care about big packets. They are prolly not
                    # coming from us anyhow
                    data, addr = sock.recvfrom(1024)
                    endTimer = time.time()

                    udpheader = receivers[sock](data)
                    if udpheader is None:
                        continue
                    srcport, dstport, udplen = udpheader

                    with cls.lock:
                        query = cls.runningQueries.get(dstport)

                    if query is None:
                        # Not one of ours, or a trace which is already done
                        continue

                    with query.lock:
                        # Only answer the probe currently waiting, anything else
                        # is a late answer to a probe which has already timed out
                        if (
                            query.srcport != srcport
                            or query.udplen != udplen
                            or query.reply is not None
                        ):
                            continue

                        timeCost = round((endTimer - query.startTimer) * 1000, 2)
                        # get the host from addr (i.e. addr[0], addr[1] is port which is 0 for ICMP)
                        query.reply = Hop(addr[0], timeCost)

                        # signal the waiting sender thread to continue
                        query.sema.release()

        # So, the listener has crashed. Should not happen, but if it does
        # the next instance of the class will start a new one.
        except Exception as e:
            print("Unexpected error in listener: {:}".format(e))
        finally:
            print("(listener) Closing down the listener due to error!")
            for sock in receivers:
                sock.close()
            with cls.lock:
                cls.listening = False

    def trun(self) -> list:
        """
        Runs the tracer.
        Raises:
            IOError
        """
        dst_ip = _resolve(self.dst)

        # print something to output if we want to
        if not self.quiet:
            text = "traceroute to {} ({}), {} hops max".format(
                self.dst, dst_ip.exploded, self.hops
            )
            print(text)

        sender = self.create_sender(dst_ip)

        # create the query object we will put in the running queries
        # dictionary. Using the class based lock
        query = Query(self.port, sender.getsockname()[1])
        with RawSocketTracer.lock:
            RawSocketTracer.runningQueries[self.port] = query

        try:
            return _trace_hops(
                dst_ip,
                self.hops,
                self.quiet,
                lambda ttl: self._probe(query, sender, dst_ip, ttl),
            )
        finally:
            with RawSocketTracer.lock:
                # Clean up our used port, both from the set and our collection of ongoing queries
                del RawSocketTracer.runningQueries[self.port]
                RawSocketTracer.ports.discard(self.port)
            sender.close()

    def _probe(self, query: Query, sender, dst_ip, ttl: int):
        """
        Sends a single UDP probe at the given ttl/hop-limit and waits for
        the listener to hand us the answer.
        Returns:
            (addr, rtt_ms) of the router/host that answered, or (None, None)
            on timeout.
        """
        if isinstance(dst_ip, ipaddress.IPv4Address):
            sender.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        else:
            sender.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, ttl)

        # payload length tells this probe apart from the earlier ones
        payload = b"\0" * ttl

        with query.lock:
            # a fresh semaphore per probe, so nothing meant for an
            # earlier probe can wake us up
            query.sema = threading.Semaphore(0)
            query.udplen = 8 + len(payload)
            query.reply = None
            query.startTimer = time.time()
            sema = query.sema

        try:
            sender.sendto(payload, (dst_ip.compressed, self.port))
        except OSError as e:
            # e.g. no route to host, counts as a hop without answer
            dprint("send error at ttl {:}: {:}".format(ttl, e))
            return None, None

        if not sema.acquire(timeout=self.timeoutSec):
            # we did not get a response
            return None, None

        with query.lock:
            return query.reply.addr, query.reply.rtt

    @classmethod
    def create_receivers(cls) -> dict:
        """
        Creates the listener's sockets
        Returns:
            dict of socket -> parser for what the socket receives, one for
            ipv4 (icmp) and, if the host supports it, one for ipv6 (icmp6)
        Raises:
            PermissionError if raw sockets are needed and we are not root
        """
        if _macos_unprivileged_available():
            socktype = socket.SOCK_DGRAM
        else:
            socktype = socket.SOCK_RAW

        s4 = socket.socket(socket.AF_INET, socktype, socket.IPPROTO_ICMP)
        receivers = {s4: cls.parse_icmp4}

        try:
            s6 = socket.socket(socket.AF_INET6, socktype, socket.IPPROTO_ICMPV6)
            receivers[s6] = cls.parse_icmp6
        except OSError as e:
            # e.g. a host without IPv6, we can still trace IPv4
            print("Cannot listen for ICMPv6, IPv6 traces will time out ({:})".format(e))

        return receivers

    def create_sender(self, ipvx):
        """
        Creates the sender socket of a trace, bound so that we know its
        source port before sending
        Returns:
            A socket instance
        """
        if isinstance(ipvx, ipaddress.IPv4Address):
            s = socket.socket(
                family=socket.AF_INET, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP
            )
            s.bind(("0.0.0.0", 0))
        elif isinstance(ipvx, ipaddress.IPv6Address):
            s = socket.socket(
                family=socket.AF_INET6, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP
            )
            s.bind(("::", 0))
        else:
            raise Exception("Unknown IP type! {:}, {:}".format(ipvx, type(ipvx)))

        return s


if __name__ == "__main__":
    # We are running this one, lets run
    # just something for the heck of it
    listargs = [
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "www.washingtonpost.com",
        "www.dn.se",
        "8.8.8.8",
        "www.dn.se",
        "8.8.8.8",
        "8.8.4.4",
    ]

    print(os.name)
    results = TraceManager.TraceAll(listargs)

    print("(MAIN) Results gotten")

    for h, r in results.items():
        print("(MAIN) One trace:({:})".format(h))
        print(r)
