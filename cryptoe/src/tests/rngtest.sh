#!/bin/bash
TEST_BLOCK_SIZE=64
TEST_BITS=5000000
TEST_BYTES=$((TEST_BITS/8))
TEST_BLOCKS=$((TEST_BYTES/TEST_BLOCK_SIZE))

CHECKFILES="rdrand2stdout.c ../rng/rdrand.c ../include/rdrand.h"
do_build()
{
    for f in ${CHECKFILES}
    do
        if [ ! -f "$f" ]
        then
            echo "This must be run in cryptoe/src/tests"
            exit 1
        fi
    done
    rm -f rdrand2stdout
    cc -o rdrand2stdout rdrand2stdout.c -Wall -Wstrict-prototypes ../rng/rdrand.c -I../include

    if [ $? != 0 ]
    then
        echo "Failed to build rdrand2stdout"
        exit 1
    fi
}

which dieharder > /dev/null 2>&1

if [ $? != 0 ]
then
    echo "dieharder not found in \$PATH"
    exit 1
fi

for arg in 1 2 3
do
    ./rdrand2stdout ${arg} | \
    dieharder -a -k 2 2>&1 | tee /tmp/dieharder-${arg}.out
done

