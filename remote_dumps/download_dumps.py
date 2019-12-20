#!/usr/bin/env python

import urllib.request
import datetime

providers = range(1, 24)
date = datetime.date.today()

dumps_dir = "dumps/"

for provider in providers:
    provider = ("{:02d}".format(provider))
    link = "http://data.ris.ripe.net/rrc{0}/latest-bview.gz".format(provider)
    dump_name = "dump_{0}_{1}.gz".format(provider, date)
    print(link)
    try:
        dump = urllib.request.urlopen(link)
    except Exception:
        print('Failed to download: ' + link)
        continue
    with open(dumps_dir + dump_name,'wb+') as output:
        output.write(dump.read())