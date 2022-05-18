import argparse
import sys
import ipaddress

import asmap

print("Reading entries...")
elems = []
with open(sys.argv[1], "r") as f:
    for line in f:
        idx = line.find('#')
        linec = line
        if idx >= 0:
            linec = line[:idx]
        linec = linec.strip()
        s = linec.split(' ')
        if len(s) == 0 or (len(s) == 1 and len(s[0]) == 0):
            continue
        if len(s) != 2 or not s[1].startswith("AS"):
            print("Line '%s' is not valid" % line)
            exit(1)
        asn = int(s[1][2:])
        if asmap._CODER_ASN.can_encode(asn):
            try:
                net = ipaddress.ip_network(s[0])
            except ValueError:
                print("Network '%s' is not valid" % net)
                exit()
        else:
            print("Skipping unencodable AS%i" % asn)
            continue
        prefix = asmap.net_to_prefix(net)
        elems.append((prefix, asn))

print("Building trie...")
elems.sort(key = lambda elem: (-len(prefix), prefix, asn))
m = asmap.ASMap()
for prefix, asn in elems:
    m.update(prefix, asn)
print("Compiling...")
bindata_filled = m.to_binary(fill=True)
bindata_unfilled = m.to_binary(fill=False)

print("Writing...")
with open("asmap-filled.dat", "wb") as f:
    f.write(bindata_filled)

with open("asmap-unfilled.dat", "wb") as f:
    f.write(bindata_unfilled)

with open("asmap-unfilled-overlap.txt", "w") as f:
    for prefix, asn in m.to_entries(fill=False, overlapping=True):
        f.write("%s AS%i\n" % (asmap.prefix_to_net(prefix), asn))

with open("asmap-unfilled-flat.txt", "w") as f:
    for prefix, asn in m.to_entries(fill=False, overlapping=False):
        f.write("%s AS%i\n" % (asmap.prefix_to_net(prefix), asn))

with open("asmap-filled-overlap.txt", "w") as f:
    for prefix, asn in m.to_entries(fill=True, overlapping=True):
        f.write("%s AS%i\n" % (asmap.prefix_to_net(prefix), asn))

with open("asmap-filled-flat.txt", "w") as f:
    for prefix, asn in m.to_entries(fill=True, overlapping=False):
        f.write("%s AS%i\n" % (asmap.prefix_to_net(prefix), asn))
