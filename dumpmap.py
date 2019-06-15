import sys
import ipaddress

IPV4_PREFIX = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])

def num_to_addr_str(num, bits):
    num <<= bits
    if num & 0xffffffffffffffffffffffff00000000 == 0xffff00000000:
        return "%s/%i" % (ipaddress.IPv4Address(num & 0xFFFFFFFF).compressed, 32 - bits)
    else:
        return "%s/%i" % (ipaddress.IPv6Address(num).compressed, 128 - bits)

def dumpmap(asmap, pos, num, bits, level, default):
    assert(len(asmap) >= pos + 1)
    opcode = 0 + asmap[pos]
    pos += 1
    if opcode == 0:
        assert(len(asmap) >= pos + 4 + opcode)
        asn = int.from_bytes(asmap[pos:pos+4+opcode], 'little')
        assert(asn != default)
        print("%s%s AS%i" % ("  " * level, num_to_addr_str(num, bits), asn))
    elif opcode == 1:
        assert(len(asmap) >= pos + 4 + opcode)
        asn = int.from_bytes(asmap[pos:pos+4+opcode], 'little')
        assert(asn != default)
        print("%s%s AS%i" % ("  " * level, num_to_addr_str(num, bits), asn))
        dumpmap(asmap, pos+4, num, bits, level+1, asn)
    elif opcode >= 240 and opcode < 248:
        assert(len(asmap) >= pos + 2)
        asn = int.from_bytes(asmap[pos:pos+2], 'little') + ((opcode - 240) << 16)
#        assert(asn != default)
        print("%s%s AS%i" % ("  " * level, num_to_addr_str(num, bits), asn))
    elif opcode >= 248:
        assert(len(asmap) >= pos + 2)
        asn = int.from_bytes(asmap[pos:pos+2], 'little') + ((opcode - 248) << 16)
#        assert(asn != default)
        print("%s%s AS%i" % ("  " * level, num_to_addr_str(num, bits), asn))
        dumpmap(asmap, pos+2, num, bits, level+1, asn)
    elif opcode < 128:
        nbits = opcode.bit_length() - 1
        dumpmap(asmap, pos, (num << nbits) + (opcode & ((1 << nbits) - 1)), bits - nbits, level, default)
    elif opcode >= 132:
        dumpmap(asmap, pos, num * 2, bits - 1, level, default)
        dumpmap(asmap, pos + opcode - 129, num * 2 + 1, bits - 1, level, default)
    else:
        offlen = opcode - 127
        assert(len(asmap) >= pos + offlen)
        offset = int.from_bytes(asmap[pos:pos+offlen], 'little')
        pos += offlen
        dumpmap(asmap, pos, num * 2, bits - 1, level, default)
        dumpmap(asmap, pos + offset, num * 2 + 1, bits - 1, level, default)

with open(sys.argv[1], "rb") as f:
    asmap = f.read()

dumpmap(asmap, 0, 0, 128, 0, None)
