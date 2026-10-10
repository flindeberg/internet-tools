"""
Tests of the traceroute packet parsing and hop logic, without any network.
Run from src/: python -m pytest ../tests
"""

import ipaddress
import os
import socket
import struct
import sys

# run from src/ (asnutils loads pyasn.dat from the working directory)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import parallelltracert as pt
from parallelltracert import RawSocketTracer as R, UnprivilegedTracer as U


def ip4(proto, payload, opts=b""):
    ihl = (20 + len(opts)) // 4
    return (
        bytes([0x40 | ihl, 0])
        + struct.pack("!H", 20 + len(opts) + len(payload))
        + b"\0" * 4
        + bytes([64, proto])
        + b"\0\0"
        + socket.inet_aton("192.0.2.1")
        + socket.inet_aton("198.51.100.1")
        + opts
        + payload
    )


def udp(sp, dp, ln):
    return struct.pack("!HHHH", sp, dp, ln, 0)


def test_icmp4_time_exceeded():
    inner = ip4(17, udp(50000, 33440, 8 + 5))
    assert R.parse_icmp4(ip4(1, bytes([11, 0, 0, 0, 0, 0, 0, 0]) + inner)) == (
        50000,
        33440,
        13,
    )


def test_icmp4_options_outer_and_inner():
    inner = ip4(17, udp(1, 2, 9), opts=b"\x01" * 8)
    assert R.parse_icmp4(
        ip4(1, bytes([3, 3]) + b"\0" * 6 + inner, opts=b"\x01" * 4)
    ) == (1, 2, 9)


def test_icmp4_rejects():
    inner = ip4(17, udp(1, 2, 9))
    assert (
        R.parse_icmp4(ip4(1, bytes([0, 0]) + b"\0" * 6 + inner)) is None
    )  # echo reply
    assert (
        R.parse_icmp4(ip4(1, bytes([11, 0]) + b"\0" * 6 + ip4(6, udp(1, 2, 9)))) is None
    )  # tcp
    assert (
        R.parse_icmp4(ip4(1, bytes([11, 0]) + b"\0" * 6 + inner[:24])) is None
    )  # truncated
    assert R.parse_icmp4(b"\x45") is None


def ip6_udp(sp, dp, ln, nh=17):
    return (
        bytes([0x60, 0, 0, 0])
        + struct.pack("!H", 8)
        + bytes([nh, 64])
        + b"\0" * 32
        + udp(sp, dp, ln)
    )


def test_icmp6():
    assert R.parse_icmp6(bytes([3, 0]) + b"\0" * 6 + ip6_udp(4000, 33450, 11)) == (
        4000,
        33450,
        11,
    )
    assert R.parse_icmp6(bytes([1, 4]) + b"\0" * 6 + ip6_udp(4000, 33450, 11)) == (
        4000,
        33450,
        11,
    )
    assert (
        R.parse_icmp6(bytes([129, 0]) + b"\0" * 6 + ip6_udp(4000, 33450, 11)) is None
    )  # echo reply
    assert (
        R.parse_icmp6(bytes([3, 0]) + b"\0" * 6 + ip6_udp(4000, 33450, 11, nh=6))
        is None
    )
    assert R.parse_icmp6(bytes([3, 0]) + b"\0" * 20) is None


def ee(origin, sockaddr):
    return struct.pack("=IBBBBII", 113, origin, 11, 0, 0, 0, 0) + sockaddr


def test_offender():
    sin = (
        struct.pack("=H", socket.AF_INET)
        + b"\0\0"
        + socket.inet_aton("203.0.113.9")
        + b"\0" * 8
    )
    assert U._parse_offender(socket.AF_INET, 2, ee(2, sin)) == "203.0.113.9"
    assert U._parse_offender(socket.AF_INET, 2, ee(1, sin)) is None  # local origin
    sin6 = (
        struct.pack("=H", socket.AF_INET6)
        + b"\0\0"
        + b"\0" * 4
        + socket.inet_pton(socket.AF_INET6, "2001:db8::7")
        + b"\0" * 4
    )
    assert U._parse_offender(socket.AF_INET6, 3, ee(3, sin6)) == "2001:db8::7"


def test_gap_limit_and_destination():
    answers = {1: ("10.0.0.1", 1.0), 2: ("10.0.0.2", 1.0)}
    hops = pt._trace_hops(
        ipaddress.ip_address("192.0.2.1"),
        30,
        True,
        lambda t: answers.get(t, (None, None)),
    )
    assert hops == ["10.0.0.1", "10.0.0.2"] + ["*"] * pt.__GAPLIMIT__
    hops = pt._trace_hops(
        ipaddress.ip_address("10.0.0.2"),
        30,
        True,
        lambda t: answers.get(t, (None, None)),
    )
    assert hops == ["10.0.0.1", "10.0.0.2"]
    # a gap shorter than the limit is passed
    answers = {1: ("10.0.0.1", 1), 5: ("10.0.0.5", 1), 6: ("192.0.2.1", 1)}
    hops = pt._trace_hops(
        ipaddress.ip_address("192.0.2.1"),
        30,
        True,
        lambda t: answers.get(t, (None, None)),
    )
    assert hops == ["10.0.0.1", "*", "*", "*", "10.0.0.5", "192.0.2.1"]


def test_requires_root():
    assert pt.requires_root() is (
        not (pt._linux_unprivileged_available() or pt._macos_unprivileged_available())
    )
    if sys.platform == "darwin":
        assert pt.requires_root() is False


def test_trace_status_best_of_ips():
    import harutilities, edgeutils

    hh = harutilities.HarHost("example.com")
    hh._ipstrace = {
        ipaddress.ip_address("192.0.2.1"): None,
        ipaddress.ip_address("2001:db8::1"): None,
    }
    hh.addTraces(
        {
            "192.0.2.1": ["10.0.0.1", "192.0.2.1"],
            "2001:db8::1": ["*", "2001:db8:ff::1", "*"],
        }
    )
    assert hh._trace == edgeutils.TraceType.full
    # v6 first hop must not be borrowed from a v4 trace
    assert all(
        ip.version == 6 for ip in hh._ipstrace[ipaddress.ip_address("2001:db8::1")]
    )


def test_hosts_from_urls():
    import harutilities

    hosts = list(harutilities.urlutils.GetHostFromString("https://Example.com:8443/x"))
    assert hosts == ["example.com"]
    assert list(
        harutilities.urlutils.GetHostFromString("http://[2001:db8::1]:8080/a")
    ) == ["2001:db8::1"]
