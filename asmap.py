import sys
import re
import ipaddress

RE = re.compile(r"(([0-9.]+|[0-9a-f:]+)/\d+) \[(AS(\d+))?[ie?]?\]")

MAX_ASN = 1000000

def AddEntry(netmask, asn, fnam, linenum, entries):
    global V4ENTRIES, V6ENTRIES
    loc = "%s:%i" % (fnam, linenum)
    if asn is None:
#        print("[WARNING] %s: no ASN for %s" % (loc, netmask), file=sys.stderr)
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
#        print("[WARNING] %s: private address %s for AS%i" % (loc, netmask, asn), file=sys.stderr)
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
        entries[0].append((network.prefixlen, int.from_bytes(network.network_address.packed, 'big'), asn, "%s:%i" % (fnam, linenum)))
    elif isinstance(network, ipaddress.IPv6Network):
        entries[1].append((network.prefixlen, int.from_bytes(network.network_address.packed, 'big'), asn, "%s:%i" % (fnam, linenum)))
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

def UpdateTree(gtree, addrlen, entries):
    for prefix, val, asn, loc in sorted(entries):
        tree = gtree
        default = None
        for i in range(prefix):
            bit = (val >> (addrlen - 1 - i)) & 1
            needs_inner = i < prefix - 1
            if tree[bit] is None:
                if needs_inner:
                    tree[bit] = [default, default]
                    tree = tree[bit]
                    continue
                else:
                    tree[bit] = (asn, loc)
                    break
            if isinstance(tree[bit], list):
                assert(needs_inner)
                tree = tree[bit]
                continue
            assert(isinstance(tree[bit], tuple))
            if tree[bit][0] == asn:
                break
            default = tree[bit]
            tree[bit] = [default, default]
            tree = tree[bit]
    return gtree

def PrependPrefix(tree, bits):
    for bit in reversed(bits):
        if bit:
            tree = [None, tree]
        else:
            tree = [tree, None]
    return tree

def CompactTree(tree):
    num = 0
    if tree is None:
        return (tree, set())
    if isinstance(tree, tuple):
        return (tree, set([tree[0]]))
    tree[0], leftas = CompactTree(tree[0])
    tree[1], rightas = CompactTree(tree[1])
    allas = leftas | rightas
    if len(allas) == 0:
        return (None, allas)
    if len(allas) == 1:
        return ((list(allas)[0], "*"), allas)
    return (tree, allas)

ZEROES = [0 for _ in range(129)]

def TreeSize(tree, depth=0):
    if tree is None:
        return (0, 0, set())
    if isinstance(tree, tuple):
        return (1, 0, set([tree[0]]))
    left_as, left_node, left_set = TreeSize(tree[0], depth + 1)
    right_as, right_node, right_set = TreeSize(tree[1], depth + 1)
    return (left_as + right_as, left_node + right_node + 1, left_set | right_set)

GLOB=[0 for _ in range(256)]

def TreeSer(tree):
    global GLOB
    # 0: 3 byte ASN ollows
    # 1: 4-byte ASN follows
    # 2-3: next bit is x
    # 4-7: next 2 bits are xx
    # 64-127: next 6 bits are xxxxxx
    # 128-131: N-byte jump offset follows
    # 132-239: jump offset 3-110
    # 240-255: 2 byte ASN follows (with high 4 bits in header)
    assert(tree is not None)
    bits = 0
    nbits = 0
    while nbits < 6 and isinstance(tree, list):
        if tree[0] is None:
            bits = bits * 2 + 1
            nbits += 1
            tree = tree[1]
        elif tree[1] is None:
            bits = bits * 2
            nbits += 1
            tree = tree[0]
        else:
            break
    if nbits > 0:
        GLOB[bits + (1 << nbits)] += 1
        return bytes([bits + (1 << nbits)]) + TreeSer(tree)
    if isinstance(tree, tuple):
        asn = tree[0]
        if asn >= 2**24:
            GLOB[1] += 1
            return bytes([1]) + asn.to_bytes(4, 'little')
        if asn >= 2**20:
            GLOB[0] += 1
            return bytes([0]) + asn.to_bytes(3, 'little')
        GLOB[240 + (asn >> 16)] += 1
        return bytes([240 + (asn >> 16), (asn >> 8) & 0xFF, asn & 0xFF])
    left = TreeSer(tree[0])
    right = TreeSer(tree[1])
    leftlen = len(left)
    assert(leftlen >= 3)
    if leftlen <= 110:
        GLOB[129 + leftlen] += 1
        return bytes([129 + leftlen]) + left + right
    leftlennum = (leftlen.bit_length() + 7) // 8
    assert(leftlennum > 0)
    assert(leftlennum <= 4)
    GLOB[127 + leftlennum] += 1
    return bytes([127 + leftlennum]) + leftlen.to_bytes(leftlennum, 'little') + left + right

def BuildTree(entries):
    v4tree, _ = CompactTree(UpdateTree([None, None], 32, entries[0]))
    v6tree, _ = CompactTree(UpdateTree(PrependPrefix(v4tree, [0 for _ in range(80)] + [1 for _ in range(16)]), 128, entries[1]))
    return v6tree

def EncodeC(b):
    if b == 34:
        return "\\\""
    elif b == 92:
        return "\\\\"
    elif b == 7:
        return "\\a"
    elif b == 8:
        return "\\b"
    elif b == 12:
        return "\\c"
    elif b == 10:
        return "\\n"
    elif b == 13:
        return "\\r"
    elif b == 9:
        return "\\t"
    elif b == 11:
        return "\\v"
    elif b >= 32 and b < 127:
        return chr(b)
    else:
        return "\\x%02x" % b

entries = [[], []]
for fnam in sys.argv[1:]:
    print("[INFO] Parsing %s" % fnam, file=sys.stderr)
    ParseDump(fnam, entries)
print("[INFO] Read %i IPv4 mappings" % len(entries[0]), file=sys.stderr)
print("[INFO] Read %i IPv6 mappings" % len(entries[1]), file=sys.stderr)
print("[INFO] Constructing trie", file=sys.stderr)
tree = BuildTree(entries)
as_count, node_count, as_set = TreeSize(tree)
print("[INFO] Number of mappings: %i" % as_count, file=sys.stderr)
print("[INFO] Number of unique AS values: %i" % len(as_set), file=sys.stderr)
print("[INFO] Number of decision nodes: %i" % node_count, file=sys.stderr)
bs = TreeSer(tree)
print("[INFO] Serialized trie is %i bytes" % len(bs), file=sys.stderr)
print("[INFO] Writing C-encoded trie to stdout", file=sys.stderr)
for i in range(256):
    x = len("".join(EncodeC((b + i) & 0xFF) for b in bs))
    print("%i: %i" % (i, x), file=sys.stderr)
bsc = "".join(EncodeC(b) for b in bs)
print("const int ASTRIE_SIZE = %i;" % len(bs))
print("const unsigned char* ASTRIE_DATA[ASTRIE_SIZE] = \"%s\";" % bsc)
#for jl in sorted(JUMPS):
#    print("[INFO] %i jumps of length %i" % (JUMPS[jl], jl), file=sys.stderr)
print("[INFO] glob: %r" % GLOB, file=sys.stderr)
for b in range(1, 7):
    print("[INFO] %i-bit matches: %i" % (b, sum(GLOB[i] for i in range(1 << b, 2 << b))))
print("[INFO] asn (16): %i" % sum(GLOB[i] for i in range(240, 256)))
print("[INFO] short jumps: %s" % ", ".join("%i" % sum(GLOB[i] for i in range(132+16*j, 148+16*j)) for j in range(6)))
print("[INFO] long jumps: %i" % sum(GLOB[i] for i in range(128, 132)))
