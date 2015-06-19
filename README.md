## CRYPTOE ##
#### A project aiming to offer a full set of cryptographic routines to make implementing crypto in any Python project easy. ####

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
1. Testing
1.1. unit tests
1.1.1. Add KW and KWP test vectors
1.2. Add assert checks in more places, where it makes sense to do so.
2. Unwrapped secret key storage
2.1. Linux: kernel per-user keyring seems ideal, with expiration
2.2. BSD: TBD
3. Add ciphers
3.1. AES will use PyCrypto's implementation
3.2. Serpent code needs CBC and CTR modes written for it, or another implementation used.
3.3. Twofish code needs CBC and CTR modes written for it, or another implementation used.

### Supported Platforms ###
1. Linux
1.1. Developed and tested on Linux/amd64
2. BSD
2.2. Tested on NetBSD 7/amd64
2.2.1. Test system lacks RDRAND, however NetBSD uses CTR_DRBG as does RDRAND.

### RNG NOTES ###
1. OS RNG is only used to feed the Fortuna CSPRNG, adapted from PyCrypto to take advantage of RDRAND.
2. Fortuna implementation has been altered to pack clock and time information into a binary string which is then run through HMAC-SHAd256 before being fed back into the accumulator.
2.1. Testing with dieharder shows this approach to provide good random numbers.

### SECRET KEY HANDLING ###
(I will fill this in as more of the secret key storage is worked out)
