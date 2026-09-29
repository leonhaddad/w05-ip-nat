#!/usr/bin/env python3
"""Week 5 · Task 1 — Subnets and longest-prefix match.

Textbook §4.3.2 (IPv4 addressing, CIDR) and §4.3.3 (forwarding).

Two things a router does with every packet: work out which prefixes the
destination falls inside, and pick the longest one. The second is the whole
of "longest prefix match", and it is the reason the internet's routing table
can hold a million entries and still be answerable.

You build both, from integers up. No `ipaddress` module - that library is
exactly the thing you are supposed to understand this week.

    python3 task1_forward.py --verify
"""
import argparse


def parse_cidr(cidr):
    """'163.152.6.0/24' -> (network as int, prefix length).

    Requirements: reject a prefix length outside 0-32, and reject an address
    whose host bits are set when they should not be (163.152.6.5/24 is a
    common way to write a host, but it is not a network).
    """
    s = cidr.strip()
    if "/" not in s:
        raise ValueError("invalid cidr")
    ip_str, plen_str = s.split("/", 1)
    try:
        plen = int(plen_str)
    except Exception:
        raise ValueError("invalid prefix length")
    if not (0 <= plen <= 32):
        raise ValueError("prefix length out of range")

    parts = ip_str.split('.')
    if len(parts) != 4:
        raise ValueError("invalid ip")
    try:
        octets = [int(p) for p in parts]
    except Exception:
        raise ValueError("invalid ip octet")
    for o in octets:
        if o < 0 or o > 255:
            raise ValueError("invalid ip octet")
    ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]

    mask = ((0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF) if plen != 0 else 0
    # host bits must be zero for a network specification
    if ip & ~mask:
        raise ValueError("address has host bits set; not a network")
    network = ip & mask
    return network, plen


def network_range(cidr):
    """'163.152.6.0/24' -> (first usable, last usable, broadcast) as strings.

    Careful at the edges. /31 and /32 do not have a usable host range in the
    ordinary sense - decide what you return and say so in observation.md.
    """
    net, plen = parse_cidr(cidr)
    mask = ((0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF) if plen != 0 else 0
    bcast = net | (~mask & 0xFFFFFFFF)

    def i2s(x):
        return f"{(x>>24)&0xFF}.{(x>>16)&0xFF}.{(x>>8)&0xFF}.{x&0xFF}"

    if plen == 32:
        first = last = net
    elif plen == 31:
        # RFC3021 allows both addresses to be used for point-to-point.
        # We return the two addresses as "usable" here.
        first = net
        last = bcast
    else:
        first = net + 1
        last = bcast - 1

    return i2s(first), i2s(last), i2s(bcast)


class ForwardingTable:
    """Longest-prefix-match forwarding.

    add(cidr, next_hop)  ·  lookup(address) -> next_hop or None

    The default route 0.0.0.0/0 matches everything and is the shortest prefix,
    so it must lose to any other match. If two entries have the same prefix
    length, the table is malformed - say what you do.
    """

    def add(self, cidr, next_hop):
        net, plen = parse_cidr(cidr)
        if not hasattr(self, 'entries'):
            self.entries = []
        self.entries.append((plen, net, next_hop))

    def lookup(self, address):
        # address is a dotted string
        parts = address.split('.')
        octets = [int(p) for p in parts]
        addr = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        best = None
        if not hasattr(self, 'entries'):
            return None
        for plen, net, hop in self.entries:
            mask = ((0xFFFFFFFF << (32 - plen)) & 0xFFFFFFFF) if plen != 0 else 0
            if addr & mask == net and (best is None or plen > best[0]):
                best = (plen, hop)
        return best[1] if best else None


# ------------------------------------------------------------------- harness
RANGE_CASES = [
    ("192.168.0.0/24",  "192.168.0.1",   "192.168.0.254",  "192.168.0.255"),
    ("10.0.0.0/8",      "10.0.0.1",      "10.255.255.254", "10.255.255.255"),
    ("172.16.32.0/20",  "172.16.32.1",   "172.16.47.254",  "172.16.47.255"),
    ("203.0.113.64/26", "203.0.113.65",  "203.0.113.126",  "203.0.113.127"),
]

TABLE = [
    ("0.0.0.0/0",       "default-gw"),
    ("10.0.0.0/8",      "campus"),
    ("10.20.0.0/16",    "eng-building"),
    ("10.20.30.0/24",   "lab-floor"),
    ("10.20.30.64/26",  "lab-rack-2"),
    ("192.168.1.0/24",  "home"),
]

LOOKUP_CASES = [
    ("10.20.30.70",   "lab-rack-2"),     # inside all four 10.x entries
    ("10.20.30.10",   "lab-floor"),
    ("10.20.99.1",    "eng-building"),
    ("10.99.0.1",     "campus"),
    ("8.8.8.8",       "default-gw"),
    ("192.168.1.77",  "home"),
]


def verify():
    fails = 0
    for cidr, first, last, bcast in RANGE_CASES:
        try:
            got = network_range(cidr)
        except NotImplementedError:
            print("  network_range is still a stub"); return 1
        except Exception as e:
            print(f"  FAIL  {cidr:<18} raised {e!r}"); fails += 1; continue
        ok = tuple(got) == (first, last, bcast)
        print(f"  {'ok  ' if ok else 'FAIL'}  {cidr:<18} {got}")
        fails += not ok

    t = ForwardingTable()
    try:
        for cidr, hop in TABLE:
            t.add(cidr, hop)
    except NotImplementedError:
        print("  ForwardingTable is still a stub"); return 1

    for addr, expect in LOOKUP_CASES:
        got = t.lookup(addr)
        ok = got == expect
        print(f"  {'ok  ' if ok else 'FAIL'}  {addr:<16} -> {got}  (want {expect})")
        fails += not ok

    print(f"\n  {len(RANGE_CASES) + len(LOOKUP_CASES) - fails}"
          f"/{len(RANGE_CASES) + len(LOOKUP_CASES)} ok")
    return 1 if fails else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    raise SystemExit(verify() if a.verify else p.print_help())
