#!/usr/bin/env python

import urllib.request
import datetime
from pathlib import Path

providers = range(1, 24)
date = datetime.date.today()

dumps_dir = "dumps/"

for provider in providers:
    provider = ("{:02d}".format(provider))
    link = "http://data.ris.ripe.net/rrc{0}/latest-bview.gz".format(provider)
    dump_name = "dump_{0}_{1}.gz".format(provider, date)
    print('{}/{} - '.format(provider, providers.stop - 1) + link)

    try:
        dump = urllib.request.urlopen(link)
        length = int(dump.getheader('content-length'))
        blocksize = max(4096, length // 1000)
        download_size_mib = length / 1024 / 1024

        Path(dumps_dir).mkdir(parents=True, exist_ok=True)
        with open(dumps_dir + dump_name, 'wb+') as output:
            downloaded_mib = 0
            while True:
                buf = dump.read(blocksize)
                if not buf:
                    break
                output.write(buf)
                downloaded_mib += len(buf) / 1024 / 1024
                if length:
                    print('    {:.2f} / {:.2f} MiB --- {:.1f}%'.format(
                        downloaded_mib, download_size_mib,
                        (downloaded_mib / download_size_mib) * 100),
                          end='\r')
            print()
    except Exception:
        print('Failed to download: ' + link)
        continue
