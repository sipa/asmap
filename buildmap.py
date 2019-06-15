import sys
import re
import ipaddress

def Parse(entries):
    for line in sys.stdin:
        line = line.split('#')[0].lstrip(' ').rstrip(' \r\n')
        prefix, asn = line.split(' ')
        assert(len(asn) > 2 and asn[:2] == "AS")
        network = ipaddress.ip_network(prefix)
        if isinstance(network, ipaddress.IPv4Network):
            entries.append((network.prefixlen + 96, int.from_bytes(network.network_address.packed, 'big') + 0xffff00000000, int(asn[2:])))
        elif isinstance(network, ipaddress.IPv6Network):
            entries.append((network.prefixlen, int.from_bytes(network.network_address.packed, 'big'), int(asn[2:])))

def UpdateTree(gtree, addrlen, entries):
    for prefix, val, asn in sorted(entries):
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
                    tree[bit] = asn
                    break
            if isinstance(tree[bit], list):
                assert(needs_inner)
                tree = tree[bit]
                continue
            assert(isinstance(tree[bit], int))
            if tree[bit] == asn:
                break
            if not needs_inner:
                tree[bit] = asn
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

def CompactTree(tree, approx=True):
    num = 0
    if tree is None:
        return (tree, set())
    if isinstance(tree, int):
        return (tree, set([tree]))
    tree[0], leftas = CompactTree(tree[0], approx)
    tree[1], rightas = CompactTree(tree[1], approx)
    allas = leftas | rightas
    if len(allas) == 0:
        return (None, allas)
    if approx and len(allas) == 1:
        return (list(allas)[0], allas)
    if isinstance(tree[0], int) and isinstance(tree[1], int) and tree[0] == tree[1]:
        return tree[0], set([tree[0]])
    return (tree, allas)

def DictMax(d):
    mk = None
    mv = None
    for k, v in d.items():
        if mv is None or v > mv:
            mk, mv = k, v
    return mk, mv
 
def PropTree(tree, approx=True):
    if tree is None:
        return (tree, {}, True)
    if isinstance(tree, int):
        return (tree, {tree: 1}, False)
    tree[0], leftcnt, leftnone = PropTree(tree[0], approx)
    tree[1], rightcnt, rightnone = PropTree(tree[1], approx)
    allcnt = {k: leftcnt.get(k, 0) + rightcnt.get(k, 0) for k in set(leftcnt) | set(rightcnt)}
    allnone = leftnone | rightnone
    maxasn, maxcount = DictMax(allcnt)
    if maxcount is not None and maxcount >= 2 and (approx or not allnone):
        return ([tree[0], tree[1], maxasn], {maxasn: 1}, allnone)
    return (tree, allcnt, allnone)

ZEROES = [0 for _ in range(129)]

def TreeSize(tree, default = None):
    if tree is None or tree == default:
        return (0, 0, 0, set())
    if isinstance(tree, int):
        return (1, 0, 0, set([tree]))
    this_as = 0
    this_set = set()
    if len(tree) > 2 and tree[2] != default:
        this_as = 1
        default = tree[2]
        this_set = set([default])
    left_as, left_inas, left_node, left_set = TreeSize(tree[0], default)
    right_as, right_inas, right_node, right_set = TreeSize(tree[1], default)
    return (left_as + right_as, this_as + left_inas + right_inas, left_node + right_node + 1, left_set | right_set | this_set)

def TreeSer(tree, default):
    # 0: 4-byte ASN ollows
    # 1: 4-byte default ASN follows
    # 2-3: next bit is x
    # 4-7: next 2 bits are xx
    # 64-127: next 6 bits are xxxxxx
    # 128-131: N-byte jump offset follows
    # 132-239: jump offset 3-110
    # 240-247: 2 byte ASN follows (with high 3 bits in header)
    # 248-255: 2 byte default ASN follows (with high 3 bits in header)
    assert(tree is not None)
    assert(not (isinstance(tree, int) and tree == default))
    bits = 0
    nbits = 0
    while nbits < 6 and isinstance(tree, list):
        if tree[0] is None or tree[0] == default:
            bits = bits * 2 + 1
            nbits += 1
            tree = tree[1]
        elif tree[1] is None or tree[1] == default:
            bits = bits * 2
            nbits += 1
            tree = tree[0]
        else:
            break
    if nbits > 0:
        return bytes([bits + (1 << nbits)]) + TreeSer(tree, default)
    if isinstance(tree, int):
        asn = tree
        if asn >= 2**19:
            return bytes([0]) + asn.to_bytes(4, 'little')
        return bytes([240 + (asn >> 16), asn & 0xFF, (asn >> 8) & 0xFF])
    newdef = bytes()
    if len(tree) > 2 and tree[2] != default:
        default = tree[2]
        if default >= 2**19:
            newdef = bytes([1]) + default.to_bytes(4, 'little')
        else:
            newdef = bytes([248 + (default >> 16), default & 0xFF, (default >> 8) & 0xFF])
        return newdef + TreeSer(tree, default)
    left = TreeSer(tree[0], default)
    right = TreeSer(tree[1], default)
    leftlen = len(left)
    assert(leftlen >= 3)
    if leftlen <= 110:
        return bytes([129 + leftlen]) + left + right
    leftlennum = (leftlen.bit_length() + 7) // 8
    assert(leftlennum > 0)
    assert(leftlennum <= 4)
    return bytes([127 + leftlennum]) + leftlen.to_bytes(leftlennum, 'little') + left + right

def BuildTree(entries, approx=True):
    tree = [None, None]
    tree = UpdateTree(tree, 128, entries)
    return tree

entries = []
print("[INFO] Loading", file=sys.stderr)
Parse(entries)
print("[INFO] Read %i prefixes" % len(entries), file=sys.stderr)
print("[INFO] Constructing trie", file=sys.stderr)
tree = BuildTree(entries)
as_count, inas_count, node_count, as_set = TreeSize(tree)
print("[INFO] Trie stats: %i inner, %i prefixes (%i leaf), %i distinct AS" % (node_count, as_count + inas_count, as_count, len(as_set)), file=sys.stderr)
print("[INFO] Compacting tree", file=sys.stderr)
tree, _ = CompactTree(tree, True)
as_count, inas_count, node_count, as_set = TreeSize(tree)
print("[INFO] Trie stats: %i inner, %i prefixes (%i leaf), %i distinct AS" % (node_count, as_count + inas_count, as_count, len(as_set)), file=sys.stderr)
print("[INFO] Computing inner prefixes", file=sys.stderr)
tree, _, _ = PropTree(tree, True)
as_count, inas_count, node_count, as_set = TreeSize(tree)
print("[INFO] Trie stats: %i inner, %i prefixes (%i leaf), %i distinct AS" % (node_count, as_count + inas_count, as_count, len(as_set)), file=sys.stderr)
bs = TreeSer(tree, None)
print("[INFO] Serialized trie is %i bytes" % len(bs), file=sys.stderr)
print("[INFO] Writing trie to stdout", file=sys.stderr)
sys.stdout.buffer.write(bs)
