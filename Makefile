ipv4.dump: ipv4.dump.xz
	xz -d <ipv4.dump.xz >ipv4.dump

ipv6.dump: ipv6.dump.xz
	xz -d <ipv6.dump.xz >ipv6.dump

demo.dat.xz: ipv4.dump ipv6.dump birdparse.py
	python3 birdparse.py ipv4.dump ipv6.dump | xz -9e >demo.dat.xz

demo.map: demo.dat.xz buildmap.py
	xz -d <demo.dat.xz | python3 buildmap.py >demo.map
