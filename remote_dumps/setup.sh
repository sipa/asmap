#!/bin/bash

mkdir dumps
mkdir paths

wget http://ris.ripe.net/source/bgpdump/libbgpdump-1.6.0.tgz
tar zxvf libbgpdump-1.6.0.tgz
rm libbgpdump-1.6.0.tgz
cd libbgpdump-1.6.0
./bootstrap.sh
make install
cd ..