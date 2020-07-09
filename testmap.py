#!/usr/bin/env python3
import sys
import random
import ipaddress

# Convert a byte array to a bit array
def DecodeBytes(byts):
    bits = []
    for byt in byts:
        for i in range(8):
            bits += [(byt >> i) & 1]
    return bits

def DecodeBits(stream, bitpos, minval, bit_sizes):
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

def DecodeType(stream, bitpos):
    return DecodeBits(stream, bitpos, 0, [0, 0, 1])

def DecodeASN(stream, bitpos):
    return DecodeBits(stream, bitpos, 1, [15, 16, 17, 18, 19, 20, 21, 22, 23, 24])

def DecodeMatch(stream, bitpos):
    return DecodeBits(stream, bitpos, 2, [1, 2, 3, 4, 5, 6, 7, 8])

def DecodeJump(stream, bitpos):
    return DecodeBits(stream, bitpos, 17, [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30])

def Interpret(asmap, num, bits):
    pos = 0
    default = None
    while True:
        assert(len(asmap) >= pos + 1)
        (opcode, pos) = DecodeType(asmap, pos)
        if opcode == 0:
            (asn, pos) = DecodeASN(asmap, pos)
            return asn
        elif opcode == 1:
            (jump, pos) = DecodeJump(asmap, pos)
            if (num >> (bits - 1)) & 1:
                pos += jump
            bits -= 1
        elif opcode == 2:
            (match, pos) = DecodeMatch(asmap, pos)
            matchlen = match.bit_length() - 1
            for bit in range(matchlen):
                if ((num >> (bits - 1)) & 1) != ((match >> (matchlen - 1 - bit)) & 1):
                    return default
                bits -= 1
        elif opcode == 3:
            (default, pos) = DecodeASN(asmap, pos)
        else:
            assert(False)



def decode_ip(ip: str) -> int:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address):
        return int.from_bytes(addr.packed, 'big') + 0xffff00000000
    elif isinstance(addr, ipaddress.IPv6Address):
        return int.from_bytes(addr.packed, 'big')


if __name__ == '__main__':
    no_args = len(sys.argv) == 1

    if no_args:
        filename = './demo.map'
    else:
        filename = sys.argv[1]

    with open(filename, "rb") as f:
        asmap = DecodeBytes(f.read())

    # If no arguments are passed, run a test on a random selection from
    # demo.dat.
    if no_args:
        expected = [
            ('8.8.8.8', 15169),
        ]
        failed = False

        with open('./demo.random.dat', 'r') as f:
            for line in f:
                (ip, asn) = line.split()[:2]
                ip = ip.split('/')[0]

                assert(asn[:2] == 'AS')
                asn = int(asn[2:])

                # Make the IP concrete and randomize it somewhat within the
                # subnet.
                if ':' not in ip:
                    ip = '.'.join(ip.split('.')[:3]) + '.{}'.format(
                        random.randint(0, 16))

                expected.append((ip, asn))

        for ip, asn in expected:
            got = Interpret(asmap, decode_ip(ip), 128)

            if got != asn:
                failed = True
                print("{} failed! Got {}, expected {}".format(
                    ip, got, asn), file=sys.stderr)
            else:
                print("{} passed".format(ip))

        sys.exit(1 if failed else 0)

    else:
        ret = Interpret(asmap, decode_ip(sys.argv[2]), 128)
        if ret:
            print("AS%i" % ret)
