import sys
import re
import ipaddress

MAX_ASN = 1000000

IPV4_PREFIX = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])

def AddEntry(netmask, asn, fnam, linenum, entries):
    loc = "%s:%i" % (fnam, linenum)
    if asn is None:
        print("[WARNING] %s: no ASN for %s" % (loc, netmask), file=sys.stderr)
        return
    if asn == 0:
        print("[WARNING] %s: ASN is zero for %s" % (loc, netmask), file=sys.stderr)
        return
    if asn >= MAX_ASN:
        print("[WARNING] %s: %s has too large AS%i" % (loc, netmask, asn), file=sys.stderr)
        return
    network = ipaddress.ip_network(netmask, True)
    if not network:
        print("[WARNING] %s: cannot parse netmask %s for AS%i" % (loc, netmask, asn), file=sys.stderr)
        return
    if network.is_multicast:
        print("[WARNING] %s: multicast address %s for AS%i" % (loc, netmask, asn), file=sys.stderr)
        return
    if network.is_private:
        print("[WARNING] %s: private address %s for AS%i" % (loc, netmask, asn), file=sys.stderr)
        return
    if network.is_unspecified:
        print("[WARNING] %s: address from unspecified range %s for AS%i" % (loc, netmask, asn), file=sys.stderr)
        return
    if network.is_reserved:
        print("[WARNING] %s: reserved address %s for AS%i" % (loc, netmask, asn), file=sys.stderr)
        return
    if network.is_loopback:
        print("[WARNING] %s: loopback address %s for AS%i" % (loc, netmask, asn), file=sys.stderr)
        return
    if isinstance(network, ipaddress.IPv4Network):
        entries.append((IPV4_PREFIX + network.network_address.packed, "%s AS%i # %s:%i" % (network.compressed, asn, fnam, linenum)))
    elif isinstance(network, ipaddress.IPv6Network):
        entries.append((network.network_address.packed, "%s AS%i # %s:%i" % (network.compressed, asn, fnam, linenum)))
    else:
        raise AssertionError("Unknown network type for %s" % netmask)

def ParseDump(fnam, entries):
    RE_INITIAL = re.compile(r"^BIRD .* ready.$")
    RE_TABLE = re.compile(r"^Table master(4|6):$")
    RE_HEADER = re.compile(r"^(([0-9.]+|[0-9a-f:]+)/\d+) +unicast +\[.*\] +\* +\(\d+\)( +\[(AS(\d+))?[ie?]?\])?$")
    RE_PATH = re.compile(r"^[\t]BGP\.as_path:(.*)$")
    RE_PATH_DECOMPOSE = re.compile(r"^[0-9 ]*?(\d+)( +\{[0-9 ]*?(\d+)\})?$")
    RE_INNER = re.compile(r"^[\t]")
    RE_INNER_ADDR = re.compile(r"^ +unicast")
    netmask = None
    asn = None
    aslevel = 0
    maskline = None
    with open(fnam) as f:
        linenum = 0
        for line in f:
            linenum += 1
            line = line.rstrip("\n\r")
            if RE_INITIAL.match(line):
                continue
            if RE_TABLE.match(line):
                continue
            match = RE_HEADER.match(line)
            if match:
                if netmask:
                    AddEntry(netmask, asn, fnam, maskline, entries)
                netmask = match[1]
                maskline = linenum
                if not match[3] or not match[4]:
                    asn = None
                    aslevel = 0
                else:
                    asn = int(match[5])
                    aslevel = 1
                continue
            match = RE_PATH.match(line)
            if match:
                if aslevel < 2:
                    decomp = RE_PATH_DECOMPOSE.match(match[1])
                    if not decomp:
                        print("[WARNING] %s:%i: cannot parse as_path %s" % (fnam, linenum, match[1]))
                    asn = int(decomp[1])
                    aslevel = 2
            match = RE_INNER.match(line)
            if match:
                continue
            match = RE_INNER_ADDR.match(line)
            if match:
                continue
            print("[WARNING] %s:%i: cannot parse %s" % (fnam, linenum, line), file=sys.stderr)
    if netmask:
        AddEntry(netmask, asn, fnam, maskline, entries)

entries = []
for fnam in sys.argv[1:]:
    print("[INFO] Parsing %s" % fnam, file=sys.stderr)
    ParseDump(fnam, entries)
print("[INFO] Parsed %i prefixes" % len(entries), file=sys.stderr)
entries.sort()
for _, s in entries:
    print(s)
