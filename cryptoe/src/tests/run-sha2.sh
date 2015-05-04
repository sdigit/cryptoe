#!/bin/sh
#CC="gcc -Wall -Werror -mavx -mtune=native -funroll-loops -I../include"
CC="gcc -Wall -Werror -I../include"

$CC -o sha2_tests sha2_tests.c ../hmac_sha2.c
$CC -o hmac_sha2_tests hmac_sha2_tests.c ../hmac_sha2.c
./sha2_tests
./hmac_sha2_tests
rm -f sha2_tests hmac_sha2_tests
