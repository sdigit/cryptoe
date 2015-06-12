from collections import OrderedDict
from math import floor, ceil
import os
import struct

from Crypto.Hash import HMAC, SHA512, SHA256
from Crypto.Protocol.KDF import PBKDF2
import hkdf

from cryptoe import Random, DEFAULT_PBKDF2_ITERATIONS
from cryptoe.exceptions import DerivationError
import time

KEY_SRC_NONE = 0
KEY_SRC_RAND = 1
KEY_SRC_PBKDF = 2
KEY_SRC_HKDF = 4

KEY_USE_NONE = 0
KEY_USE_ROOT = 1
KEY_USE_DERIVATION = 2
KEY_USE_HMAC = 4
KEY_USE_ENCRYPTION = 8
KEY_USE_WRAPPING = 16
KEY_USE_IV_SEED = 32

KEY_ALG_NONE = 0
KEY_ALG_CIPHER = 1
KEY_ALG_MAC = 2
KEY_ALG_BLK_AES = 4
KEY_ALG_BLK_TWOFISH = 8
KEY_ALG_BLK_SERPENT = 16
KEY_ALG_HMAC_SHA256 = 32
KEY_ALG_HMAC_SHA384 = 64
KEY_ALG_HMAC_SHA512 = 128

PRF_NONE = 0
PRF_HMAC_SHA256 = 1
PRF_HMAC_SHA384 = 2
PRF_HMAC_SHA512 = 4

KEY_INFO_SRC = OrderedDict({
    KEY_SRC_RAND: 'Fortuna',
    KEY_SRC_PBKDF: 'PBKDF2',
    KEY_SRC_HKDF: 'HKDF',
})

KEY_INFO_USE = OrderedDict({
    KEY_USE_ROOT: 'Master Key',
    KEY_USE_DERIVATION: 'Key Derivation Key',
    KEY_USE_HMAC: 'Message Digest Key',
    KEY_USE_ENCRYPTION: 'Symmetric Cipher Key',
    KEY_USE_WRAPPING: 'Key Encryption Key',
    KEY_USE_IV_SEED: 'IV Generation Key',
})

KEY_INFO_PRF = OrderedDict({
    PRF_NONE: 'No PRF used',
    PRF_HMAC_SHA512: 'PRF was HMAC-SHA512',
})

KEY_INFO_ALG = OrderedDict({
    KEY_ALG_NONE: 'Algorithm unspecified or not applicable',
    KEY_ALG_CIPHER: 'Symmetric Cipher',
    KEY_ALG_MAC: 'Keyed Message Authentication',
    KEY_ALG_BLK_AES: 'Advanced Encryption Standard',
    KEY_ALG_BLK_TWOFISH: 'Twofish',
    KEY_ALG_BLK_SERPENT: 'Serpent',
    KEY_ALG_HMAC_SHA256: 'SHA-256',
    KEY_ALG_HMAC_SHA384: 'SHA-384',
    KEY_ALG_HMAC_SHA512: 'SHA-512',
})


def gather_easy_entropy(size=256):
    assert (size == 256 or size == 128)
    hm = HMAC.new('\x00' * (size / 8), digestmod=SHA256)  # Avoid extension attacks
    # 64 bits from time
    tm = time.time()
    hm.update(struct.pack('!L', int(2 ** 30 * (tm - floor(tm)))))
    hm.update(struct.pack('!L', int(ceil(tm))))
    del tm
    # 32 from clock
    ck = time.clock()
    hm.update(struct.pack('!L', int(2 ** 30 * (ck - floor(ck)))))
    del ck
    # 32 from PID * PPID
    pp = (os.getpid() * os.getppid()) % (2 ** 32 - 1)
    hm.update(struct.pack('!L', pp))
    del pp
    return hm.digest()[:size / 8]


def generate_key(size=256):
    """
    Generate a key suitable for cryptographic use per NIST SP800-133

    :return: key
    """
    assert (size == 256 or size == 128)
    rbg = Random.new()
    u = rbg.read(size / 8)
    v = gather_easy_entropy(size)
    k = ''.join(map(chr, map(lambda x: ord(x[0]) ^ ord(x[1]), zip(u, v))))
    return k


def create_mk(pw, salt='', rounds=DEFAULT_PBKDF2_ITERATIONS, dklen=32):
    """
    Create a master key from user input, using PBKDF2.
    Return a list in the form of [Key object,salt]

    :param pw: password or passphrase
    :param salt: salt for PBKDF2 (if not specified, will be generated randomly)
    :param rounds: number of iterations of the PRF
    :param dklen: desired key length in bytes
    :type pw: str
    :type salt: str
    :type rounds: int
    :type dklen: int
    :rtype: MasterKey
    """
    if dklen < 16 or dklen > 1024:
        raise DerivationError('Requested key must be between 16 and 1024 bytes')
    if salt == '':
        kdf_salt = Random.new().read(64)
    elif len(salt) < 16:
        raise RuntimeError('salt smaller than minimum')
    else:
        kdf_salt = salt

    prf = lambda k, s: HMAC.new(k, s, SHA512).digest()

    key = PBKDF2(pw, kdf_salt, dkLen=dklen, count=rounds, prf=prf)
    return [key, salt]


def create_dk(key, dklen=32, kdf_info='', hkdf_salt=''):
    """
    Derive a subkey of the current key using HKDF. Add it to the subkeys list.
    If no salt is specified, use a random salt of the same length as the current key.

    Returns a list in the form of [Key object,salt]

    :param hkdf_salt: Random hkdf_salt for HKDF expansion
    :param dklen: length of derived key
    :type hkdf_salt: str
    :type dklen: int
    """
    if dklen < 16 or dklen > 1024:
        raise DerivationError('Requested key must be between 16 and 1024 bytes')
    if hkdf_salt == '':
        hkdf_salt = Random.new().read(dklen)
    prk = hkdf.hkdf_extract(hkdf_salt, key.get_key())
    dk = hkdf.hkdf_expand(prk, info=kdf_info, length=dklen)
    return dk
