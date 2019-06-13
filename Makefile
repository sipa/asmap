demo.dat.xz: ipv4.dump ipv6.dump
	python3 birdparse ipv4.dump ipv6.dump | xz -9e >demo.dat.xz
