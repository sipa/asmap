#!/usr/bin/env bash

for mrt in `ls dumps`; do
    echo "processing $mrt..."
    OUT=$mrt
    /usr/bin/env bgpdump -vm dumps/$mrt | cut -d '|' -f '6,7' > paths/$OUT
done

