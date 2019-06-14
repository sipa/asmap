import sys
import ipaddress

IPV4_PREFIX = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])

def num_to_addr_str(num, bits):
    num <<= bits
    if num & 0xffffffffffffffffffffffff00000000 == 0xffff00000000:
        return "%s/%i" % (ipaddress.IPv4Address(num & 0xFFFFFFFF).compressed, 32 - bits)
    else:
        return "%s/%i" % (ipaddress.IPv6Address(num).compressed, 128 - bits)

def dumpmap(asmap, pos=0, num=0, bits=128):
    assert(len(asmap) >= pos + 1)
    opcode = int(asmap[pos])
    pos += 1
    if opcode < 2:
        assert(len(asmap) >= pos + 2 + opcode)
        print("%s AS%i" % (num_to_addr_str(num, bits), int.from_bytes(asmap[pos:pos+2+opcode], 'little')))
    elif opcode >= 240:
        assert(len(asmap) >= pos + 2)
        print("%s AS%i" % (num_to_addr_str(num, bits), int.from_bytes(asmap[pos:pos+2], 'big') + ((opcode - 240) << 16)))
    elif opcode < 128:
        nbits = opcode.bit_length() - 1
        dumpmap(asmap, pos, (num << nbits) + (opcode & ((1 << nbits) - 1)), bits - nbits)
    elif opcode >= 132:
        dumpmap(asmap, pos, num * 2, bits - 1)
        dumpmap(asmap, pos + opcode - 129, num * 2 + 1, bits - 1)
    else:
        offlen = opcode - 127
        assert(len(asmap) >= pos + offlen)
        offset = int.from_bytes(asmap[pos:pos+offlen], 'little')
        pos += offlen
        dumpmap(asmap, pos, num * 2, bits - 1)
        dumpmap(asmap, pos + offset, num * 2 + 1, bits - 1)

with open(sys.argv[1], "rb") as f:
    asmap = f.read()

dumpmap(asmap)
