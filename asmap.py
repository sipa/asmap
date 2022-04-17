import sys
import ipaddress
from collections import namedtuple

Entry = namedtuple('Entry', (
    # The length of the network prefix in bits.
    # For example, 2a01:4f9:c010:19eb::/64 has prefix_len=64.
    # This field must come first, as we'll be sorting entries based on
    # their prefix length.
    'prefix_len',

    # An int containing the bits of the network address. Every
    # address represents a sequence of 128 bits. IPv4 addresses
    # are mapped into the IPv6 range ::ffff:0:0/96.
    'prefix',

    # An int for the autonomous system (AS) number.
    'asn',
))

def txtdata_to_entries(txtdata):
    """
    Given a string corresponding to the contents of a file of the format

        1.0.0.0/24 AS13335 # ipv4.dump:4856343
        1.0.4.0/22 AS56203 # ipv4.dump:2759291
        ...

    Ignoring comments following '#'. Creates an Entry object for each line.
    Maps IPv4 networks into IPv6 space.

    Returns:
        A list containing the Entry objects.
    """
    ret = []
    for line in txtdata.splitlines():
        line = line.split('#')[0].lstrip(' ').rstrip(' \r\n')
        prefix, asn = line.split(' ')
        assert(len(asn) > 2 and asn[:2] == "AS")
        network = ipaddress.ip_network(prefix)

        prefix_len = network.prefixlen
        prefix = int.from_bytes(network.network_address.packed, 'big')

        # Map an IPv4 prefix into IPv6 space.
        if isinstance(network, ipaddress.IPv4Network):
            prefix_len += 96
            prefix += 0xffff00000000

        assert (prefix & ((1 << (128 - prefix_len)) - 1)) == 0
        ret.append(Entry(prefix_len, prefix >> (128 - prefix_len), int(asn[2:])))

    return ret

def entries_to_txtdata(entries):
    """Convert list of entries to text format."""
    ret = []
    for prefix_len, prefix, asn in entries:
        prefix <<= 128 - prefix_len
        if prefix_len >= 96 and (prefix >> 32) == 0xffff:
            net = ipaddress.IPv4Network((prefix & 0xffffffff, prefix_len - 96), True)
        else:
            net = ipaddress.IPv6Network((prefix, prefix_len), True)
        ret.append("%s AS%i\n" % (net, asn))
    return "".join(ret)

# Trie representation for asmap
#
# The tree is represented as a recursive structure consisting of list objects.
# Every node is either:
# - []: to indicate "undefined" (no ASN)
# - [int]: to indicate "this entire range maps has ASN int"
# - [left,right]: with left and right new nodes

def entries_to_trie(entries):
    """
    Construct a trie format representation of the entries in entries.
    In case entries overlap, the smaller range (larger prefix_len) takes
    priority.

    Args:
        entries: The network prefix -> ASN mappings to encode.
    Returns:
        The trie.
    """
    trie = []
    for prefix_len, prefix, asn in sorted(entries):
        node = trie
        # Iterate through each bit in the network prefix, starting with the
        # most significant bit.
        for i in range(prefix_len):
            bit = (prefix >> (prefix_len - 1 - i)) & 1
            if len(node) == 0:
                node.append([])
                node.append([])
            elif len(node) == 1:
                oldasn = node[0]
                node.clear()
                node.append([oldasn])
                node.append([oldasn])
            node = node[bit]
        node.clear()
        node.append(asn)

    def simplify(node):
        if len(node) < 2:
            return
        simplify(node[0])
        simplify(node[1])
        if len(node[0]) == 2:
            return
        if node[0] == node[1]:
            if len(node[0]) == 0:
                node.clear()
            else:
                v = node[0][0]
                node.clear()
                node.append(v)

    simplify(trie)

    return trie

def trie_to_entries_flat(trie, optimize):
    """Convert a trie to a list of Entry objects that do not overlap."""
    def recurse(node, prefix_len, prefix):
        ret = []
        if len(node) == 1:
            ret = [Entry(prefix_len, prefix, node[0])]
        elif len(node) == 2:
            ret = recurse(node[0], prefix_len + 1, prefix << 1)
            ret += recurse(node[1], prefix_len + 1, (prefix << 1) | 1)
            if optimize and len(ret) > 1:
                asns = set(x.asn for x in ret)
                if len(asns) == 1:
                    ret = [Entry(prefix_len, prefix, list(asns)[0])]
        return ret
    return recurse(trie, 0, 0)

def trie_to_entries_minimal(trie, optimize):
    """Convert a trie to a minimal list of Entry objects, exploiting the overlap rule."""
    def recurse(node, prefix_len, prefix):
        if len(node) == 0:
            return ({None if optimize else -1: []}, True)
        elif len(node) == 1:
            return ({node[0]: [], None: [Entry(prefix_len, prefix, node[0])]}, False)
        else:
            ret = {}
            left, lhole = recurse(node[0], prefix_len + 1, prefix << 1)
            right, rhole = recurse(node[1], prefix_len + 1, (prefix << 1) | 1)
            hole = lhole or rhole
            for ctx in set(left) & set(right):
                ret[ctx] = left[ctx] + right[ctx]
            if None in right:
                for ctx in left:
                    if ctx not in ret or len(left[ctx]) + len(right[None]) < len(ret[ctx]):
                        ret[ctx] = left[ctx] + right[None]
            if None in left:
                for ctx in right:
                    if ctx not in ret or len(left[None]) + len(right[ctx]) < len(ret[ctx]):
                        ret[ctx] = left[None] + right[ctx]
            if optimize or not hole:
                gen = ret.get(None, None)
                for ctx in ret:
                    if ctx is not None and ctx != -1:
                        if gen is None or len(ret[ctx]) + 1 < len(gen):
                            gen = [Entry(prefix_len, prefix, ctx)] + ret[ctx]
                if gen is not None:
                    ret[None] = gen
                ret = {ctx:entries for (ctx, entries) in ret.items() if ctx is None or gen is None or len(entries) < len(gen)}
            else:
                ret = {ctx:entries for (ctx, entries) in ret.items() if ctx is None or ctx == -1}
            return (ret, hole)
    res, _ = recurse(trie, 0, 0)
    if -1 in res:
        return res[-1]
    return res[None]

def trie_subsumes(actual, require):
    if len(require) == 0:
        return True
    if len(require) == 1:
        if len(actual) == 0:
            return False
        if len(actual) == 1:
            return require[0] == actual[0]
        return trie_subsumes(actual[0], require) and trie_subsumes(actual[1], require)
    if len(actual) == 2:
        return trie_subsumes(actual[0], require[0]) and trie_subsumes(actual[1], require[1])
    return trie_subsumes(actual, require[0]) and trie_subsumes(actual, require[1])

class AsmapInstruction:
    # A return instruction, encoded as [0], returns a constant ASN. It is followed by
    # an integer using the ASN encoding.
    RETURN = 0
    # A jump instruction, encoded as [1,0] inspects the next unused bit in the input
    # and either continues execution, or skips a specified number of bits. It is followed
    # by an integer, and then two subprograms. The integer uses jump encoding and
    # corresponds to the length of the first subprogram (so it can be skipped).
    JUMP = 1
    # A match instruction, encoded as [1,1,0] inspects 1 or more of the next unused bits
    # in the input with its argument. If they all match, execution continues. If they do
    # not, failure is returned. If a default instruction has been executed before, instead
    # of failure the default instruction's argument is returned. It is followed by an
    # integer in match encoding, and a subprogram. That value is at least 2 bits and at
    # most 9 bits. An n-bit value signifies matching (n-1) bits in the input with the lower
    # (n-1) bits in the match value.
    MATCH = 2
    # A default instruction, encoded as [1,1,1] sets the default variable to its argument,
    # and continues execution. It is followed by an integer in ASN encoding, and a subprogram.
    DEFAULT = 3
    # Not an actual instruction, but a way to encode the empty program. This cannot be a
    # subprogram of anything else.
    END = 4

def encode_bits(val, minval, bit_sizes) -> [int]:
    """
    Perform a variable-length encoding of a value to bits, least significant
    bit first.

    For each `bit_sizes` passed, attempt to encode the value with that number
    of bits + 1. Normalize the encoded value by `minval` to potentially save
    bits - the value will be corrected during decoding.

    Returns:
        a list of bits representing the value to encode.
    """
    val -= minval
    ret = []
    for pos in range(len(bit_sizes)):
        bit_size = bit_sizes[pos]

        # If the value will not fit in `bit_size` bits, absorb the largest
        # value for this bitsize and continue to the next smallest size.
        if val >= (1 << bit_size):
            val -= (1 << bit_size)
            ret += [1]
        else:
            # If we aren't encoding the largest possible value per the largest
            # bitsize...
            if (pos + 1 < len(bit_sizes)):
                ret += [0]

            # Use remaining bits to encode the rest of val.
            for b in range(bit_size):
                ret += [(val >> (bit_size - 1 - b)) & 1]
            return ret

    # Couldn't fit val into any of the bit_sizes
    assert(False)

def encode_bits_size(val, minval, bit_sizes):
    """Predict the length of encode_bits(val, minval, bit_sizes)."""
    val -= minval
    ret = 0
    for pos in range(len(bit_sizes)):
        bit_size = bit_sizes[pos]
        if val >= (1 << bit_size):
            val -= (1 << bit_size)
            ret += 1
        else:
            if (pos + 1 < len(bit_sizes)):
                ret += 1
            return ret + bit_size
    assert False

def decode_bits(stream, bitpos, minval, bit_sizes):
    val = minval
    for pos in range(len(bit_sizes)):
        bit_size = bit_sizes[pos]
        if pos + 1 < len(bit_sizes):
            bit = stream[bitpos]
            bitpos += 1
        else:
            bit = 0
        if bit:
            val += (1 << bit_size)
        else:
            for b in range(bit_size):
                bit = stream[bitpos]
                bitpos += 1
                val += bit << (bit_size - 1 - b)
            return (val, bitpos)
    assert(False)

BIT_SIZES_TYPE = [0, 0, 1]
BIT_SIZES_ASN = list(range(15, 25))
BIT_SIZES_MATCH = list(range(1, 9))
BIT_SIZES_JUMP = list(range(5, 31))

def encode_type(v):
    return encode_bits(v, 0, BIT_SIZES_TYPE)

def encode_type_size(v):
    return encode_bits_size(v, 0, BIT_SIZES_TYPE)

def decode_type(stream, bitpos):
    return decode_bits(stream, bitpos, 0, BIT_SIZES_TYPE)

def encode_asn(v):
    return encode_bits(v, 1, BIT_SIZES_ASN)

def encode_asn_size(v):
    return encode_bits_size(v, 1, BIT_SIZES_ASN)

def decode_asn(stream, bitpos):
    return decode_bits(stream, bitpos, 1, BIT_SIZES_ASN)

def encode_match(v):
    return encode_bits(v, 2, BIT_SIZES_MATCH)

def encode_match_size(v):
    return encode_bits_size(v, 2, BIT_SIZES_MATCH)

def decode_match(stream, bitpos):
    return decode_bits(stream, bitpos, 2, BIT_SIZES_MATCH)

def encode_jump(v):
    return encode_bits(v, 17, BIT_SIZES_JUMP)

def encode_jump_size(v):
    return encode_bits_size(v, 17, BIT_SIZES_JUMP)

def decode_jump(stream, bitpos):
    return decode_bits(stream, bitpos, 17, BIT_SIZES_JUMP)

class AsmapEncoding:
    """A class representing an encoded asmap program in parsed form."""

    def __init__(self, ins, arg1=None, arg2=None):
        """
        Construct a new asmap encoding. Possibilities are:
        - AsmapEncoding(AsmapInstruction.RETURN, asn)
        - AsmapEncoding(AsmapInstruction.JUMP, encoding_0, encoding_1)
        - AsmapEncoding(AsmapInstruction.MATCH, val, encoding)
        - AsmapEncoding(AsmapInstruction.DEFAULT, asn, encoding)
        - AsmapEncoding(AsmapInstruction.END)
        """
        self.ins = ins
        self.arg1 = arg1
        self.arg2 = arg2
        if ins == AsmapInstruction.RETURN:
            assert isinstance(arg1, int)
            assert arg2 is None
            self.size = encode_type_size(ins) + encode_asn_size(arg1)
        elif ins == AsmapInstruction.JUMP:
            assert isinstance(arg1, AsmapEncoding)
            assert isinstance(arg2, AsmapEncoding)
            self.size = encode_type_size(ins) + encode_jump_size(arg1.size) + arg1.size + arg2.size
        elif ins == AsmapInstruction.DEFAULT:
            assert isinstance(arg1, int)
            assert isinstance(arg2, AsmapEncoding)
            self.size = encode_type_size(ins) + encode_asn_size(arg1) + arg2.size
        elif ins == AsmapInstruction.MATCH:
            assert isinstance(arg1, int)
            assert isinstance(arg2, AsmapEncoding)
            self.size = encode_type_size(ins) + encode_match_size(arg1) + arg2.size
        elif ins == AsmapInstruction.END:
            assert arg1 is None
            assert arg2 is None
            self.size = 0
        else:
            assert False

    def __str__(self):
        if self.ins == AsmapInstruction.END:
            return "E"
        if self.ins == AsmapInstruction.JUMP:
            return "J(%s,%s)" % (self.arg1, self.arg2)
        if self.ins == AsmapInstruction.MATCH:
            return "M%i(%s)" % (self.arg1, self.arg2)
        if self.ins == AsmapInstruction.DEFAULT:
            return "D%i(%s)" % (self.arg1, self.arg2)
        if self.ins == AsmapInstruction.RETURN:
            return "R%i" % (self.arg1)
        assert False

    @staticmethod
    def make_end():
        """Constructor for an encoding of just the END instruction."""
        return AsmapEncoding(AsmapInstruction.END)

    @staticmethod
    def make_leaf(val):
        """Constructor for an encoding of just the RETURN instruction."""
        assert val is not None
        return AsmapEncoding(AsmapInstruction.RETURN, val)

    @staticmethod
    def make_branch(left, right):
        """
        Construct a program running the left or right subprogram, based on an input bit.
        It exploits shortcuts that are possible in the encoding, and use either a JUMP,
        MATCH, or END instruction."""

        if left.ins == AsmapInstruction.END and right.ins == AsmapInstruction.END:
            return left
        if left.ins == AsmapInstruction.END:
            if right.ins == AsmapInstruction.MATCH and right.arg1 <= 0xFF:
                return AsmapEncoding(right.ins, right.arg1 + (1 << right.arg1.bit_length()), right.arg2)
            return AsmapEncoding(AsmapInstruction.MATCH, 3, right)
        if right.ins == AsmapInstruction.END:
            if left.ins == AsmapInstruction.MATCH and left.arg1 <= 0xFF:
                return AsmapEncoding(left.ins, left.arg1 + (1 << (left.arg1.bit_length() - 1)), left.arg2)
            return AsmapEncoding(AsmapInstruction.MATCH, 2, left)
        return AsmapEncoding(AsmapInstruction.JUMP, left, right)

    @staticmethod
    def make_default(val, sub):
        """
        Construct a program running the specified subprogram, with the specified default
        value. It exploits shortcuts that are possible in the encoding, and will use
        either a DEFAULT or a RETURN instruction."""
        assert val is not None and val > 0
        if sub.ins == AsmapInstruction.END:
            return AsmapEncoding(AsmapInstruction.RETURN, val)
        if sub.ins == AsmapInstruction.RETURN or sub.ins == AsmapInstruction.DEFAULT:
            return sub
        return AsmapEncoding(AsmapInstruction.DEFAULT, val, sub)

    def encode(self):
        """Construct the actual bit encoding of this program. Returns a list of ints."""
        if self.ins == AsmapInstruction.RETURN:
            return encode_type(self.ins) + encode_asn(self.arg1)
        elif self.ins == AsmapInstruction.JUMP:
            return encode_type(self.ins) + encode_jump(self.arg1.size) + self.arg1.encode() + self.arg2.encode()
        elif self.ins == AsmapInstruction.DEFAULT:
            return encode_type(self.ins) + encode_asn(self.arg1) + self.arg2.encode()
        elif self.ins == AsmapInstruction.MATCH:
            return encode_type(self.ins) + encode_match(self.arg1) + self.arg2.encode()
        elif self.ins == AsmapInstruction.END:
            return []

def encoding_to_trie(encoding, default=None):

    if encoding.ins == AsmapInstruction.END:
        return [] if default is None else [default]
    elif encoding.ins == AsmapInstruction.RETURN:
        return [encoding.arg1]
    elif encoding.ins == AsmapInstruction.JUMP:
        return [encoding_to_trie(encoding.arg1, default), encoding_to_trie(encoding.arg2, default)]
    elif encoding.ins == AsmapInstruction.MATCH:
        val = encoding.arg1
        sub = encoding_to_trie(encoding.arg2, default)
        while val >= 2:
            bit = val & 1
            val >>= 1
            fail = [] if default is None else [default]
            if bit:
                sub = [fail, sub]
            else:
                sub = [sub, fail]
        return sub
    elif encoding.ins == AsmapInstruction.DEFAULT:
        return encoding_to_trie(encoding.arg2, encoding.arg1)
    else:
        assert False

def trie_to_encoding(trie, optimize):
    """Convert a trie to asmap encoding."""
    def recurse(node):
        if len(node) == 0:
            return ({(None if optimize else -1): AsmapEncoding.make_end()}, True)
        elif len(node) == 1:
            return ({None: AsmapEncoding.make_leaf(node[0]), node[0]: AsmapEncoding.make_end()}, False)
        else:
            ret = {}
            left, lhole = recurse(node[0])
            right, rhole = recurse(node[1])
            hole = lhole or rhole
            for ctx in set(left) & set(right):
                ret[ctx] = AsmapEncoding.make_branch(left[ctx], right[ctx])
            if None in left:
                for ctx in right:
                    cand = AsmapEncoding.make_branch(left[None], right[ctx])
                    if ctx not in ret or cand.size < ret[ctx].size:
                        ret[ctx] = cand
            if None in right:
                for ctx in left:
                    cand = AsmapEncoding.make_branch(left[ctx], right[None])
                    if ctx not in ret or cand.size < ret[ctx].size:
                        ret[ctx] = cand
            if optimize or not hole:
                gen = ret.get(None, None)
                for ctx in ret:
                    if ctx is not None and ctx != -1:
                        cand = AsmapEncoding.make_default(ctx, ret[ctx])
                        if gen is None or cand.size < gen.size:
                            gen = cand
                if gen is not None:
                    ret[None] = gen
                ret = {ctx:enc for (ctx,enc) in ret.items() if ctx is None or gen is None or enc.size < gen.size}
            else:
                ret = {ctx:enc for (ctx,enc) in ret.items() if ctx is None or ctx == -1}
            return (ret, hole)
    res, _ = recurse(trie)
    if -1 in res:
        return res[-1]
    if None in res:
        return res[None]

PREC = [
    (0,1), (1,0),
    (0,2), (2,0),
    (0,3), (1,2), (2,1), (3,0),
    (0,4), (1,3), (3,1), (4,0),
    (0,5), (1,4), (2,3), (3,2),
    (4,1), (5,0), (0,6), (1,5),
    (2,4), (4,2), (5,1), (6,0)
]

def isqrt(s):
    if s == 0: return 0
    x0 = 1 << (((s.bit_length() - 1) >> 1) + 1)
    x1 = (x0 + s // x0) >> 1
    while x1 < x0:
        x0 = x1
        x1 = (x0 + s // x0) >> 1
    return x0

def int_to_trie(v):
    if v == 0:
        return []
    if v < 4:
        return [v]
    v -= 4
    if v < len(PREC):
        a, v = PREC[v]
    else:
        a = (isqrt(8 * v - 31) - 1) >> 1
        v -= (a * (a + 1)) >> 1
    return [int_to_trie(a), int_to_trie(v)]

def encode_bytes(bits):
    """Encode a sequence of bits as a sequence of bytes."""
    val = 0
    nbits = 0
    ret = []
    for bit in bits:
        val += (bit << nbits)
        nbits += 1
        if nbits == 8:
            ret.append(val)
            val = 0
            nbits = 0
    if nbits:
        ret.append(val)
    return bytes(ret)

#a=int(sys.argv[1])
#t=int(sys.argv[2])
#while True:
#    trie = int_to_trie(a)
#    a += t
#    ent_flat_unopt = trie_to_entries_flat(trie, False)
#    assert(entries_to_trie(ent_flat_unopt) == trie)
#    ent_flat_opt = trie_to_entries_flat(trie, True)
#    assert(trie_subsumes(actual=entries_to_trie(ent_flat_opt), require=trie))
#    ent_min_unopt = trie_to_entries_minimal(trie, False)
#    assert(entries_to_trie(ent_min_unopt) == trie)
#    ent_min_opt = trie_to_entries_minimal(trie, True)
#    assert(trie_subsumes(actual=entries_to_trie(ent_min_opt), require=trie))
#    enc_unopt = trie_to_encoding(trie, False)
#    assert(encoding_to_trie(enc_unopt) == trie)
#    enc_opt = trie_to_encoding(trie, True)
#    assert(trie_subsumes(actual=encoding_to_trie(enc_opt), require=trie))
#    if (a % 100000) < t:
#        print(a, enc_unopt.size, enc_opt.size)
#
#exit()

print("Reading file...")
txtdata = sys.stdin.read()
print("Parsing file...")
entries = txtdata_to_entries(txtdata)
print("Building trie...")
trie = entries_to_trie(entries)
print("Building flat entries list...")
e_flat_unopt = trie_to_entries_flat(trie, False)
assert(entries_to_trie(e_flat_unopt) == trie)
print(len(e_flat_unopt))
print("Building optimized flat entries list...")
e_flat_opt = trie_to_entries_flat(trie, True)
assert(trie_subsumes(actual=entries_to_trie(e_flat_opt), require=trie))
print(len(e_flat_opt))
print("Building minimal entries list...")
e_min_unopt = trie_to_entries_minimal(trie, False)
assert(entries_to_trie(e_min_unopt) == trie)
print(len(e_min_unopt))
print("Building optimized minimal entries list...")
e_min_opt = trie_to_entries_minimal(trie, True)
assert(trie_subsumes(actual=entries_to_trie(e_min_opt), require=trie))
print(len(e_min_opt))
print("Building encoding...")
enc_unopt = trie_to_encoding(trie, False)
assert(encoding_to_trie(enc_unopt) == trie)
print(enc_unopt.size)
print("Building optimized encoding...")
enc_opt = trie_to_encoding(trie, True)
print(enc_opt.size)
assert(trie_subsumes(require=trie, actual=encoding_to_trie(enc_opt)))

with open("asmap_flat_unopt.txt", "w") as f:
    f.write(entries_to_txtdata(e_flat_unopt))
with open("asmap_flat_opt.txt", "w") as f:
    f.write(entries_to_txtdata(e_flat_opt))
with open("asmap_min_unopt.txt", "w") as f:
    f.write(entries_to_txtdata(e_min_unopt))
with open("asmap_min_opt.txt", "w") as f:
    f.write(entries_to_txtdata(e_min_opt))
with open("asmap_enc_unopt.txt", "wb") as f:
    f.write(encode_bytes(enc_unopt.encode()))
with open("asmap_enc_opt.txt", "wb") as f:
    f.write(encode_bytes(enc_opt.encode()))
