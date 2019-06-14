import sys
import ipaddress

IPV4_PREFIX = bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])

def interpret(asmap, num, bits):
    pos = 0
    while True:
        assert(len(asmap) >= pos + 1)
        opcode = int(asmap[pos])
        pos += 1
        if opcode < 2:
            assert(len(asmap) >= pos + 3 + opcode)
            return int.from_bytes(asmap[pos:pos+3+opcode], 'little')
        elif opcode >= 240:
            assert(len(asmap) >= pos + 2)
            return int.from_bytes(asmap[pos:pos+2], 'big') + ((opcode - 240) << 16)
        elif opcode < 128:
            nbits = opcode.bit_length() - 1
            assert(bits >= nbits)
            if (opcode ^ (num >> (bits - nbits))) & ((1 << nbits) - 1):
                return None
            bits -= nbits
        elif opcode >= 132:
            assert(bits >= 1)
            if (num >> (bits - 1)) & 1:
                pos += opcode - 129
            bits -= 1
        else:
            assert(bits >= 1)
            offlen = opcode - 127
            assert(len(asmap) >= pos + offlen)
            offset = int.from_bytes(asmap[pos:pos+offlen], 'little')
            pos += offlen
            if (num >> (bits - 1)) & 1:
                pos += offset
            bits -= 1

with open(sys.argv[1], "rb") as f:
    asmap = f.read()
addr = ipaddress.ip_address(sys.argv[2])
if isinstance(addr, ipaddress.IPv4Address):
    num = int.from_bytes(IPV4_PREFIX + addr.packed, 'big')
elif isinstance(addr, ipaddress.IPv6Address):
    num = int.from_bytes(addr.packed, 'big')

ret = interpret(asmap, num, 128)
if ret:
    print("AS%i" % ret)
