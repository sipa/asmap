import sys
import re
import ipaddress

def Parse(entries):
    for line in sys.stdin:
        line = line.split('#')[0].rstrip(' \r\n')
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
    if isinstance(tree, int):
        return (tree, set([tree]))
    tree[0], leftas = CompactTree(tree[0])
    tree[1], rightas = CompactTree(tree[1])
    allas = leftas | rightas
    if len(allas) == 0:
        return (None, allas)
    if len(allas) == 1:
        return (list(allas)[0], allas)
    return (tree, allas)

ZEROES = [0 for _ in range(129)]

def TreeSize(tree, depth=0):
    if tree is None:
        return (0, 0, set())
    if isinstance(tree, int):
        return (1, 0, set([tree]))
    left_as, left_node, left_set = TreeSize(tree[0], depth + 1)
    right_as, right_node, right_set = TreeSize(tree[1], depth + 1)
    return (left_as + right_as, left_node + right_node + 1, left_set | right_set)

def TreeSer(tree):
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
        return bytes([bits + (1 << nbits)]) + TreeSer(tree)
    if isinstance(tree, int):
        asn = tree
        if asn >= 2**24:
            return bytes([1]) + asn.to_bytes(4, 'little')
        if asn >= 2**20:
            return bytes([0]) + asn.to_bytes(3, 'little')
        return bytes([240 + (asn >> 16), asn & 0xFF, (asn >> 8) & 0xFF])
    left = TreeSer(tree[0])
    right = TreeSer(tree[1])
    leftlen = len(left)
    assert(leftlen >= 3)
    if leftlen <= 110:
        return bytes([129 + leftlen]) + left + right
    leftlennum = (leftlen.bit_length() + 7) // 8
    assert(leftlennum > 0)
    assert(leftlennum <= 4)
    return bytes([127 + leftlennum]) + leftlen.to_bytes(leftlennum, 'little') + left + right

def BuildTree(entries):
    tree, _ = CompactTree(UpdateTree([None, None], 128, entries))
    return tree

entries = []
print("[INFO] Loading")
Parse(entries)
print("[INFO] Read %i prefixes" % len(entries), file=sys.stderr)
print("[INFO] Constructing trie", file=sys.stderr)
tree = BuildTree(entries)
as_count, node_count, as_set = TreeSize(tree)
print("[INFO] Number of prefixes: %i" % as_count, file=sys.stderr)
print("[INFO] Number of distinct AS values: %i" % len(as_set), file=sys.stderr)
print("[INFO] Number of decision nodes: %i" % node_count, file=sys.stderr)
bs = TreeSer(tree)
print("[INFO] Serialized trie is %i bytes" % len(bs), file=sys.stderr)
print("[INFO] Writing trie to stdout", file=sys.stderr)
sys.stdout.buffer.write(bs)
