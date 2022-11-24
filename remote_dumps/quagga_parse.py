#!/usr/bin/env python3

import os
from bgpdumpy import BGPDump, TableDumpV2

for file in os.listdir('dumps'):
    if 'dump' not in file:
        continue
    with BGPDump(f'dumps/{file}') as bgp:
            print(f"Processing {file}...")
            to_dump = ""
            for entry in bgp:
                if isinstance(entry.body, TableDumpV2):
                    prefix = '%s/%d' % (entry.body.prefix, entry.body.prefixLength)
                    list_ASN = set([
                        route.attr.asPath
                        for route
                        in entry.body.routeEntries])
                else:
                    prefix = '%s/%d' % (entry.body.prefix, entry.body.mask)
                    list_ASN = [entry.body.peerAS]

                for item in list(list_ASN):
                    to_dump += f'{prefix}|{item}\n'

            with open(f'paths/{file}', 'w') as w_file:
                w_file.write(to_dump)
