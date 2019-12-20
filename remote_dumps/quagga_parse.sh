#!/bin/bash

for mrt in `ls dumps`; do
    /bin/echo -n "processing $mrt...      "
    OUT=$mrt
    /usr/local/bin/bgpdump -vm dumps/$mrt | cut -d '|' -f '6,7' > paths/$OUT
done

