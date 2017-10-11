## CRYPTOE ##
#### A project aiming to offer a full set of cryptographic routines to make implementing crypto in any Python project easy. ####

## DO NOT USE THIS CODE UNLESS YOU ARE SERIOUS ABOUT TRUSTING UNPROVEN CRYPTO ##

Cryptoe is intended to offer an easy to use API to common cryptographic tasks, as well as key storage that follows the
NIST requirements as closely as possible[1]

A secondary goal is the avoidance of OpenSSL and also the avoidance of code licensed under GPL and similar highly restrictive licenses.

Cryptoe is written to take advantage of RDRAND if present. If not present, heavier use will be made of /dev/urandom. Fortuna is used in either case, the primary difference is speed.

[1]: Currently, there are two known major deviations from NIST:
     1. Fortuna is used for random numbers, which is not an approved random bit generator.
     2. SHAd256 is not an approved hash algorithm (though it's a way of using an approved hash algorithm)

### Dependencies ###
Cryptoe requires the following additional python packages:
1. PyCrypto (PBKDF2, much of Fortuna, SHA2 hashes other than SHAd256)
2. whirlpool (to provide an alternative to SHA-512)
3. sqlalchemy (key storage)

### TODO ###
1. add unit tests for KeyDB and KeyMgmt
2. add unit tests for KeyWrap (along with test vectors)
3. Add assert checks in more places, where it makes sense to do so.
4. Decide how to deal with unwrapped secrets on FreeBSD and NetBSD as they do not have a kernel keyring API akin to Linux keyutils
5. Add ciphers
 - AES (PyCrypto provides AES with AESNI support, so use that)
 - Serpent (Cipher itself is already in-tree, however cipher modes are not.)
 - Twofish (Cipher itself is already in-tree, however cipher modes are not.)

### Supported Platforms ###
1. Linux/amd64 (kernel 4.0.4 on Linux Mint)
2. NetBSD/amd64 (7.0_BETA)

### Testing needed ###
1. Big-endian system(s): NetBSD/sparc64 most likely. Output will need to be compared to that from NetBSD/amd64 and Linux/amd64.

### RNG NOTES ###
1. OS RNG is only used to feed the Fortuna CSPRNG, adapted from PyCrypto to take advantage of RDRAND.
2. Where RDRAND is not present, OS RNG is one of three entropy sources used for Fortuna

### SECRET KEY HANDLING ###
* On Linux, keyutil(2) provides the necessary functionality.
