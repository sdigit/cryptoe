## CRYPTOE ##
#### A project aiming to offer a full set of cryptographic routines to make implementing crypto in any Python project easy. ####

Cryptoe is intended to offer an easy to use API to common cryptographic tasks, as well as key storage that follows the
NIST requirements as closely as possible[1]

A secondary goal is the avoidance of OpenSSL and also the avoidance of code licensed under GPL and similar highly restrictive licenses.

[1]: Currently, there are two known major deviations from NIST:
     1. Fortuna is used for random numbers, which is not an approved random bit generator.
     2. SHAd256 is not an approved hash algorithm (though it's a way of using an approved hash algorithm)

### Dependencies ###
Cryptoe requires the following additional python packages:
1. PyCrypto
2. whirlpool
3. sqlalchemy

Cryptoe is written to take advantage of RDRAND if present. If not present, heavier use will be made of /dev/urandom. Fortuna is used in either case, the primary difference is speed.

### TODO ###
1. Add unit tests
1.1. KW and KWP test vectors
2. Secret key storage
2.1. Determine best method or combination of methods to store unwrapped secret keys. Currently thinking of using the Linux kernel keystore, but what about BSD?
3. Add ciphers
3.1. AES will use PyCrypto's implementation
3.2. Serpent code needs CBC and CTR modes written for it, or another implementation used.
3.3. Twofish code needs CBC and CTR modes written for it, or another implementation used.
