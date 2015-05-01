## CRYPTOE: ##
#### A project aiming to offer a full set of cryptographic routines to make implementing crypto in any Python project easy. ####

To install:
> cd cryptoe && python setup.py install --user
(I don't recommend installing this system-wide yet, as it's still WIP while I merge code out of other projects and clean
it up)

### CAVEATS ###
Due to heavy reliance on Intel RDRAND, this WILL NOT work on a system lacking it.

### TODO ###
1. Make the RNG configurable. I want to limit the choices, at least at first, so that I can test each (rather than simply having it take anything with a getrandbits function)
2. Add unit tests, primarily selftests for the algorithms
3. Add RNG test results. Right now I have a lot of data from dieharder on RDRAND, as that's why Cryptoe uses it, but for the sake of completeness it should include dieharder tests of all supported RNGs.
4. Add a generic KMS class for storage of key data and key metadata in a secure manner. This will most likely be done first for sqlite3 and psycopg2.



