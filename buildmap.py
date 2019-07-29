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

# Add a list of (prefixlen, addrbits, asn) entries to a tree
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

# Remove redundancy from a tree.
# If approx is True, unassigned ranges may get reassigned to arbitrary ASNs.
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

# Get the (key, value) with maximum value from a dict.
def DictMax(d):
    mk = None
    mv = None
    for k, v in d.items():
        if mv is None or v > mv:
            mk, mv = k, v
    return mk, mv

# Annotate internal nodes in the tree with the most common leafs below it.
# The binary serialization later uses this.
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

# Compute some statistics about the tree size.
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

def EncodeBits(val, minval, bit_sizes):
    val -= minval
    ret = []
    for pos in range(len(bit_sizes)):
        bit_size = bit_sizes[pos]
        if val >= (1 << bit_size):
            val -= (1 << bit_size)
            ret += [1]
        else:
            if (pos + 1 < len(bit_sizes)):
                ret += [0]
            for b in range(bit_size):
                ret += [(val >> (bit_size - 1 - b)) & 1]
            return ret
    assert(False)

#ASN=dict()
#MATCH=dict()
#JUMP=dict()
#
#def Optimal(m):
#    left = sum(v for k,v in m.items())
#    xlow = min(k for k,v in m.items())
#    low = xlow
#    bit_lengths = []
#    while left > 0:
#        for bit_length in range(32):
#            cnt = sum(v for k,v in m.items() if k >= low and k < low + (1 << bit_length))
#            if cnt * 2 >= left:
#                bit_lengths += [bit_length]
#                low += (1 << bit_length)
#                left -= cnt
#                break
#    return (xlow, bit_lengths)

def EncodeType(v):
    return EncodeBits(v, 0, [0, 0, 1])

def EncodeASN(v):
#    ASN.setdefault(v, 0)
#    ASN[v] += 1
    return EncodeBits(v, 1, [15, 16, 17, 18, 19, 20, 21, 22, 23, 24])

def EncodeMatch(v):
#    MATCH.setdefault(v, 0)
#    MATCH[v] += 1
    return EncodeBits(v, 2, [1, 2, 3, 4, 5, 6, 7, 8])

def EncodeJump(v):
#    JUMP.setdefault(v, 0)
#    JUMP[v] += 1
    return EncodeBits(v, 17, [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30])

def EncodeBytes(bits):
    val = 0
    nbits = 0
    bytes = []
    for bit in bits:
        val += (bit << nbits)
        nbits += 1
        if (nbits == 8):
            bytes += [val]
            val = 0
            nbits = 0
    if nbits:
        bytes += [val]
    return bytes

def DecodeBytes(byts):
    bits = []
    for byt in byts:
        for i in range(8):
            bits += [(byt >> i) & 1]
    return bytes

def TreeSer(tree, default):
    match = 1
    assert(tree is not None)
    assert(not (isinstance(tree, int) and tree == default))
    while isinstance(tree, list) and match <= 0xFF:
        if tree[0] is None or tree[0] == default:
            match = (match << 1) + 1
            tree = tree[1]
        elif tree[1] is None or tree[1] == default:
            match = (match << 1) + 0
            tree = tree[0]
        else:
            break
    if match >= 2:
        return EncodeType(2) + EncodeMatch(match) + TreeSer(tree, default)
    if isinstance(tree, int):
        return EncodeType(0) + EncodeASN(tree)
    if len(tree) > 2 and tree[2] != default:
        return EncodeType(3) + EncodeASN(tree[2]) + TreeSer(tree, tree[2])
    left = TreeSer(tree[0], default)
    right = TreeSer(tree[1], default)
    return EncodeType(1) + EncodeJump(len(left)) + left + right

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

ser = TreeSer(tree, None)
print("[INFO] Total bits: %i" % (len(ser)), file=sys.stderr)
sys.stdout.buffer.write(bytes(EncodeBytes(ser)))
#print("[INFO] Optimal MATCH params: %i %r" % Optimal(MATCH), file=sys.stderr)
#print("[INFO] Optimal JUMP params: %i %r" % Optimal(JUMP), file=sys.stderr)
#print("[INFO] Optimal ASN params: %i %r" % Optimal(ASN), file=sys.stderr)
