## CRYPTOE ##
#### A project aiming to offer a full set of cryptographic routines to make implementing crypto in any Python project easy. ####

Cryptoe isn't intended to be useful on its own. It is intended to provide an easily integrated crypto library for use in other projects, with as little dependency on external libraries (eg. OpenSSL) as I can manage.
When ready for release, this will ship with scripts to validate it against common test vectors. NIST/FIPS will be first.

To install:
> cd cryptoe && python setup.py install --user


### CAVEATS ###
1. The first priority of this codebase is correctness of implementation. As such, it has been written to assume certain things about types, compiler behavior, etc.
2. Chips lacking RDRAND are out of luck until I have the RNG modules ready.
3. This will not be the fastest implementation of any algorithm it includes, as it's being written for correctness and verifiability rather than performance.


### Dependencies ###
I am trying to keep this list to only what is needed for security.
- If on a glibc system, you will need libbsd for strlcpy/strlcat and friends.
- An Intel CPU supporting RDRAND
- OpenSSL (for now)


### TODO ###
1. Add dieharder results
1. - rdrand, C: rdrand_get_n_64
1. - rdrand, C: rdrand_get_n_32
1. - rdrand, C: rdrand_get_bytes
1. - rdrand, Python: rdrand_get_n_64
1. - rdrand, Python: rdrand_get_n_32
1. - rdrand, Python: rdrand_get_bytes
1. - ParanoiaRNG: essentially Fortuna, using SHAd256 digests of inputs (so far beats everything else in dieharder, it's slower but not by enough to preclude usage as RNG)
3. Modularize the HMAC code, so (for example) whirlpool can be substituted for an SHA2 algorithm
4. Add block ciphers:
4. - Serpent (CBC mode) (code is present but not yet exposed via python API)
5. Add hashes:
5. - Whirlpool
5. - SHA-3 (Keccak) once it's finalized
6. RNG, standardization + OS support
6. - Add SP800-90A CTR_DRBG where OS doesn't already offer a direct API for it (as an option, perhaps a default)
6. - Linux (adapt code to use the crypto API for CTR_DRBG and failback to python implementation
6. - NetBSD PRNG is already CTR_DRBG: we can use that directly: refactor C to know this.
6. - FreeBSD & OpenBSD (portability is good)
7. Testing
7. - Add unit tests
7. - Add assertions. Blow up rather than work stupidly.
7. - Fire up old gear and see what happens on MSB (sparc32, sparc64): likely need endianness handling.
