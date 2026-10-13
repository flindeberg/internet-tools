"""
Offline test of the whole pipeline: HAR -> hosts -> DNS -> traces -> AS
lookup -> edges. DNS, traces and RDAP are stubbed, the AS lookup uses the
routing data snapshot in git (src/pyasn.dat).
Run from src/: python -m pytest ../tests
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
import asnutils
import dns.resolver
import harutilities

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "two_hosts.har")

DNS = {
    ("dns.google", "A"): ["8.8.8.8"],
    ("dns.google", "AAAA"): ["2001:4860:4860::8888"],
    ("one.one.one.one", "A"): ["1.1.1.1"],
}

# home router, a hop that does not answer, an IXP LAN (not in BGP, so it
# goes to RDAP), and the destination; and one trace that stops answering
TRACES = {
    "8.8.8.8": ["192.168.1.1", "*", "194.68.128.73", "8.8.8.8"],
    "1.1.1.1": ["192.168.1.1", "*", "*", "*", "*", "*"],
    "2001:4860:4860::8888": ["*", "2001:7f8:d::1", "2001:4860:4860::8888"],
}


def vcard_entity(handle, roles, name):
    return {
        "handle": handle,
        "roles": roles,
        "vcardArray": [
            "vcard",
            [["version", {}, "text", "4.0"], ["fn", {}, "text", name]],
        ],
    }


# trimmed from what RIPE's RDAP returned (via rdap.arin.net) in 2026-10
RDAP = {
    "194.68.128.73": {
        "startAddress": "194.68.128.0",
        "endAddress": "194.68.128.255",
        "name": "SE-GIX",
        "country": "SE",
        "remarks": [
            {
                "description": [
                    "Stockholm Interconnect FDDI",
                    "$Id: inetnum_194.68.128.0-24,v 1.1 2010-05-21 08:53:56 nico Exp $",
                ]
            }
        ],
        "entities": [
            vcard_entity(
                "NAC16-RIPE", ["administrative"], "Netnod Administrative Contact"
            ),
            vcard_entity("NETNOD-MNT", ["registrant"], "NETNOD-MNT"),
        ],
    },
    "2001:7f8:d::1": {
        "startAddress": "2001:7f8:d::",
        "endAddress": "2001:7f8:d:ffff:ffff:ffff:ffff:ffff",
        "name": "SE-NETNODIX-20021108",
        "country": "SE",
        "remarks": [
            {
                "description": [
                    "$Id: inet6num:2001:7f8:d::-48,v 1.5 2005/05/18 08:18:51 liman Exp $"
                ]
            }
        ],
        "entities": [
            vcard_entity(
                "NAC16-RIPE", ["administrative"], "Netnod Administrative Contact"
            ),
            vcard_entity("NETNOD-MNT", ["registrant"], "NETNOD-MNT"),
            vcard_entity("ORG-NIE1-RIPE", ["registrant"], "Netnod AB"),
        ],
    },
}


class _Address:
    def __init__(self, address):
        self.address = address


def _query(host, rdtype):
    if (host, rdtype) not in DNS:
        raise dns.resolver.NoAnswer()
    return [_Address(a) for a in DNS[(host, rdtype)]]


class _RdapResponse:
    def __init__(self, ip):
        self.content = json.dumps(RDAP[ip]).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class _RdapSession:
    def mount(self, *args):
        pass

    def get(self, url):
        return _RdapResponse(url.rsplit("/", 1)[1])


def _reset_asn_state():
    # class-level caches, and AsInfo's default dicts which all instances share
    asnutils.ASNLookup._ASNLookup__p = None
    asnutils.ASNLookup._ASNLookup__unannounced.clear()
    asnutils.AsInfo().ipas.clear()
    asnutils.AsInfo().asas.clear()


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setattr(harutilities.dns.resolver, "query", _query)
    monkeypatch.setattr(
        harutilities.TraceManager,
        "TraceAll",
        classmethod(lambda cls, ips: {ip: list(TRACES[ip]) for ip in ips}),
    )
    monkeypatch.setattr(asnutils.requests, "session", lambda: _RdapSession())
    # the snapshot in git, so that the test gives the same result everywhere
    monkeypatch.setattr(asnutils, "pyasn_current_name", lambda: asnutils.PYASN_SNAPSHOT)
    _reset_asn_state()
    yield
    _reset_asn_state()


def _label(node):
    # AS nodes are "<name>\n(<asn>, <cc>)". Keep "(<asn>, <cc>)", as AS
    # names change between routing data snapshots; but for unannounced
    # networks (from RDAP) "<name> (<cc>)", as their negative "ASNs" are
    # handed out in lookup order
    if "\n" not in node:
        return node
    name, number = node.split("\n")
    asn, cc = number.strip("()").split(", ")
    return "{} ({})".format(name, cc) if asn.startswith("-") else number


def _edges(checker):
    return {
        (e.edgeType.name, _label(e.node1), _label(e.node2)) for e in checker.getEdges()
    }


def test_load():
    checker = harutilities.CheckHAR()
    checker.Load(FIXTURE)
    result = checker.GetResult()
    assert result.requests == 3
    assert len(result.cookies) == 1
    assert result.start == "2026-10-13T12:00:00.000Z"
    # header and body sizes summed per host; the port in the url is dropped
    assert {h: v.size for h, v in result.hosts.items()} == {
        "dns.google": 30800,
        "one.one.one.one": 1100,
    }


def test_pipeline_ipv4_and_ipv6(offline):
    checker = harutilities.CheckHAR(ipv6=True)
    checker.Load(FIXTURE)
    checker.cook()

    assert _edges(checker) == {
        # first hops; the ipv6 trace has no first hop of its own (and must
        # not borrow the ipv4 one), so it starts at the IXP
        ("start", "localhost", "(0, XX)"),
        ("start", "localhost", "Netnod (SE)"),
        # routes between AS:s; the IXP LANs are not in BGP and named from
        # RDAP: the first remark, skipping RCS "$Id" lines, else the
        # registrant organisation ("Netnod AB", cleaned), not a maintainer
        ("asn", "(0, XX)", "Stockholm Interconnect FDDI (SE)"),
        ("asn", "Stockholm Interconnect FDDI (SE)", "(15169, US)"),
        ("asn", "Netnod (SE)", "(15169, US)"),
        ("asn", "(0, XX)", "(13335, US)"),
        # reached over ipv4 or ipv6 counts as reached, the other did not answer
        ("host", "(15169, US)", "dns.google"),
        ("ihost", "(13335, US)", "one.one.one.one"),
        ("cc", "United States", "(15169, US)"),
        ("cc", "United States", "(13335, US)"),
        ("cc", "Sweden", "Stockholm Interconnect FDDI (SE)"),
        ("cc", "Sweden", "Netnod (SE)"),
        ("company", "Google", "(15169, US)"),
        ("company", "Cloudflare", "(13335, US)"),
        # also when the cleaned name is exactly a known company
        ("company", "Netnod", "Netnod (SE)"),
    }


def test_pipeline_ipv4_only(offline):
    checker = harutilities.CheckHAR()
    checker.Load(FIXTURE)
    checker.cook()
    edges = _edges(checker)
    assert not any("Netnod (SE)" in e for e in edges)
    assert ("host", "(15169, US)", "dns.google") in edges
