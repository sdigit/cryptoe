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
2. hkdf [introduces a dependency on OpenSSL until it can be replaced with another implementation]
3. sqlalchemy
4. whirlpool

Cryptoe assumes the following hardware is present:
1. An Intel CPU which implements the RDRAND instruction

### TODO ###
1. Add unit tests
1.1. SHAd256 test vectors (done, not yet in git)
1.2. Whirlpool test vectors
1.3. KW and KWP test vectors
2. Add ciphers
2.1. AES will use PyCrypto's implementation
2.2. Serpent code needs CBC and CTR modes written for it, or another implementation used.
2.3. Twofish code needs CBC and CTR modes written for it, or another implementation used.
