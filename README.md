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

### TODO ###
1. Whirlpool test vectors
2. FS&K SHAd256 test vectors (From FreeBSD kernel? need to find some)
