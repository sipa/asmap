import datetime
import urllib.request
import shutil
import tempfile
import os
import os.path

FILES = {
    "routeviews.bz2": "http://archive.routeviews.org/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-3.bz2": "http://archive.routeviews.org/route-views3/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-4.bz2": "http://archive.routeviews.org/route-views4/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-5.bz2": "http://archive.routeviews.org/route-views5/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-6.bz2": "http://archive.routeviews.org/route-views6/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-amsix.bz2": "http://archive.routeviews.org/route-views.amsix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-chicago.bz2": "http://archive.routeviews.org/route-views.chicago/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-chile.bz2": "http://archive.routeviews.org/route-views.chile/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-eqix.bz2": "http://archive.routeviews.org/route-views.eqix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-flix.bz2": "http://archive.routeviews.org/route-views.flix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-gorex.bz2": "http://archive.routeviews.org/route-views.gorex/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-kixp.bz2": "http://archive.routeviews.org/route-views.kixp/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-linx.bz2": "http://archive.routeviews.org/route-views.linx/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-napafrica.bz2": "http://archive.routeviews.org/route-views.napafrica/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-nwax.bz2": "http://archive.routeviews.org/route-views.nwax/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-phoix.bz2": "http://archive.routeviews.org/route-views.phoix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-telxatl.bz2": "http://archive.routeviews.org/route-views.telxatl/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-wide.bz2": "http://archive.routeviews.org/route-views.wide/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-sydney.bz2": "http://archive.routeviews.org/route-views.sydney/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-saopaulo.bz2": "http://archive.routeviews.org/route-views.saopaulo/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-saopaulo-2.bz2": "http://archive.routeviews.org/route-views2.saopaulo/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-sg.bz2": "http://archive.routeviews.org/route-views.sg/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-perth.bz2": "http://archive.routeviews.org/route-views.perth/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-sfmix.bz2": "http://archive.routeviews.org/route-views.sfmix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-soxrs.bz2": "http://archive.routeviews.org/route-views.soxrs/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-mwix.bz2": "http://archive.routeviews.org/route-views.mwix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-rio.bz2": "http://archive.routeviews.org/route-views.rio/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-fortaleza.bz2": "http://archive.routeviews.org/route-views.fortaleza/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-gixa.bz2": "http://archive.routeviews.org/route-views.gixa/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-bdix.bz2": "http://archive.routeviews.org/route-views.bdix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-bknix.bz2": "http://archive.routeviews.org/route-views.bknix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-uaeix.bz2": "http://archive.routeviews.org/route-views.uaeix/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "routeviews-ny.bz2": "http://archive.routeviews.org/route-views.ny/bgpdata/%Y.%m/RIBS/rib.%Y%m%d.0000.bz2",
    "ripe-00.gz": "https://data.ris.ripe.net/rrc00/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-01.gz": "https://data.ris.ripe.net/rrc01/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-03.gz": "https://data.ris.ripe.net/rrc03/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-04.gz": "https://data.ris.ripe.net/rrc04/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-05.gz": "https://data.ris.ripe.net/rrc05/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-06.gz": "https://data.ris.ripe.net/rrc06/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-07.gz": "https://data.ris.ripe.net/rrc07/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-10.gz": "https://data.ris.ripe.net/rrc10/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-11.gz": "https://data.ris.ripe.net/rrc11/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-12.gz": "https://data.ris.ripe.net/rrc12/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-13.gz": "https://data.ris.ripe.net/rrc13/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-14.gz": "https://data.ris.ripe.net/rrc14/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-15.gz": "https://data.ris.ripe.net/rrc15/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-16.gz": "https://data.ris.ripe.net/rrc16/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-18.gz": "https://data.ris.ripe.net/rrc18/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-19.gz": "https://data.ris.ripe.net/rrc19/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-20.gz": "https://data.ris.ripe.net/rrc20/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-21.gz": "https://data.ris.ripe.net/rrc21/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-22.gz": "https://data.ris.ripe.net/rrc22/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-23.gz": "https://data.ris.ripe.net/rrc23/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-24.gz": "https://data.ris.ripe.net/rrc24/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-25.gz": "https://data.ris.ripe.net/rrc25/%Y.%m/bview.%Y%m%d.0000.gz",
    "ripe-26.gz": "https://data.ris.ripe.net/rrc26/%Y.%m/bview.%Y%m%d.0000.gz",
}

NOW = datetime.datetime.now() - datetime.timedelta(seconds=300000)
NOWSTR = NOW.strftime("%Y%m%d")
DIRNAME = "data-%s/" % NOWSTR

if not os.path.exists(DIRNAME):
    os.mkdir(DIRNAME)
for filename, url in FILES.items():
    fullpath = DIRNAME + filename
    eurl = NOW.strftime(url)
    if not os.path.exists(fullpath):
        print("Downloading %s from %s" % (filename, eurl))
        if os.path.exists(fullpath + ".part"):
            os.remove(fullpath + ".part")
        try:
            with urllib.request.urlopen(eurl) as response, open(fullpath + ".part", "wb") as out_file:
                shutil.copyfileobj(response, out_file)
            os.rename(fullpath + ".part", fullpath)
        except OSError as err:
            print("Failed to download %s: %s" % (filename, err))
