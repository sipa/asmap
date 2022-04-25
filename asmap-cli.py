import argparse
import sys

from asmap import ASMap, ASNEntry

print("Reading entries...")
entries = []
with open(sys.argv[1], "r") as f:
    for line in f:
        entry = ASNEntry.from_string(line)
        if entry:
            entries.append(entry)

print("Loading...")
asmap = ASMap.from_entries(entries)
print("Compiling...")
bindata = asmap.to_binary(fill=False)

print("Writing...")
with open(sys.argv[2], "wb") as f:
    f.write(bindata)
