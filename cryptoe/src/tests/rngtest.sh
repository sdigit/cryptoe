#!/bin/bash
CHECKFILES="rdrand2stdout.c ../rng/rdrand.c ../include/rdrand.h"
for f in ${CHECKFILES}
do
    if [ ! -f "$f" ]
    then
        echo "This must be run in cryptoe/src/tests"
        exit 1
    fi
done

cc -o rdrand2stdout rdrand2stdout.c -Wall -Wstrict-prototypes ../rng/rdrand.c -I../include

if [ $? != 0 ]
then
    echo "Failed to build rdrand2stdout"
    exit 1
fi

which dieharder > /dev/null 2>&1

if [ $? != 0 ]
then
    echo "dieharder not found in \$PATH"
    exit 1
fi

# test rdrand_get_n_32, rdrand_get_n_64, and rdrand_get_bytes
RDRAND_ARGS="32 64 bytes"
CHUNK_SIZE=32 # 32 bytes per chunk, since 256 bits is a useful amount
for arg in ${RDRAND_ARGS}
do
    TS=$(date +"%s.%n")
    OUTFILE="dieharder-RDRAND-${arg}x${CHUNK_SIZE}-${TS}.txt"
    ./rdrand2stdout ${arg} ${CHUNK_SIZE} | \
    dieharder -g 200 -a | \
    tee ${OUTFILE}
    fgrep WEAK ${OUTFILE} > weak-${CHUNK_SIZE}.txt
done

