__author__ = 'Sean Davis <dive@endersgame.net>'

from Crypto.Util import Counter
from Crypto.Hash import HMAC, SHA512
from Crypto.Cipher import AES
from Crypto import Random
import math
import struct
import rdrand

DEFAULT_PBKDF2_ITERATIONS = 20000
QUAD = struct.Struct('>Q')
SUPPORTED_RNGS = ['rdrand', 'pycrypto', 'devrandom', 'devurandom']


def long2ba(val):
    """
    Convert a long integer into a bytearray

    :param val: a long integer
    :return: bytearray
    """
    B = bytearray()
    n = abs(val)
    while n > 0:
        B += struct.pack('<B', n % 256)
        n >>= 8
    return bytearray(reversed(B))


def ba2long(val):
    """
    Convert a bytearray into a long integer

    :param val: a bytearray
    :return: long
    """
    N = 0
    for b in val:
        N <<= 8
        if type(b) == int:
            N += b
        elif type(b) == str:
            N += ord(b)
    return long(N)


def _pycrypto_rand_bytes(sz):
    return Random.new().read(sz)


def _devrandom_read_bytes(sz):
    return open('/dev/urandom', 'rb').read(sz)


def _devurandom_read_bytes(sz):
    return open('/dev/random', 'rb').read(sz)


def rndbytes(sz, rng=None):
    """
    Return sz random bytes
    :param sz: how many bytes
    :return: bytearray
    """
    if rng not in RNG_MAP:
        raise ValueError('Unsupported RNG')
    return RNG_MAP[rng](sz)


def __pack_for_kdf(string):
    return struct.pack('>' + ('s' * len(string)), string)


def __prf(k, s):
    h = HMAC.new(k, digestmod=SHA512)
    h.update(s)
    r = h.digest()
    del h
    return r


def ctrkdf(key, label, context, sz=256):
    n = int(math.ceil(float(sz) / float(32)))
    prev = b''
    result = ''
    i = 1
    if n > (pow(2, 256) - 1):
        raise ValueError
    fmt = {
        'lbl': '>%s' % 's' * len(label),
        'ctx': '>%s' % 's' * len(context),
    }
    # noinspection PyTypeChecker
    fmt = fmt['lbl'] + 0x00 + fmt['ctx']
    while i <= n:
        ko = __prf(key, struct.pack('>L', i) + fmt + struct.pack('>L', sz))
        result = result + ko
        i += 1
        del ko
    del n
    del prev
    del i
    return b''.join(result)[:sz / 8]


def ctr_enc(k, msg):
    ctr = Counter.new(128)
    aes = AES.new(k, AES.MODE_CTR, counter=ctr)
    ct = aes.encrypt(msg)
    del ctr
    del aes
    return ct


def ctr_dec(k, msg):
    ctr = Counter.new(128)
    aes = AES.new(k, AES.MODE_CTR, counter=ctr)
    ct = aes.decrypt(msg)
    del ctr
    del aes
    return ct


# noinspection PyTypeChecker
def aes_unwrap_key_and_iv(kek, wrapped):
    n = len(wrapped) / 8 - 1
    R = [None] + [wrapped[i * 8:i * 8 + 8] for i in range(1, n + 1)]
    A = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek).decrypt
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            ciphertext = QUAD.pack(A ^ (n * j + i)) + R[i]
            B = decrypt(ciphertext)
            A = QUAD.unpack(B[:8])[0]
            R[i] = B[8:]
    return "".join(R[1:]), A


def aes_unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    if key_iv != iv:
        raise ValueError("Integrity Check Failed: " + hex(key_iv) + " (expected " + hex(iv) + ")")
    return key


def aes_unwrap_key_withpad(kek, wrapped):
    key, key_iv = aes_unwrap_key_and_iv(kek, wrapped)
    key_iv = "{0:016X}".format(key_iv)
    if key_iv[:8] != "A65959A6":
        raise ValueError("Integrity Check Failed: " + key_iv[:8] + " (expected A65959A6)")
    key_len = int(key_iv[8:], 16)
    return key[:key_len]


# noinspection PyTypeChecker
def aes_wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
    n = len(plaintext) / 8
    R = [None] + [plaintext[i * 8:i * 8 + 8] for i in range(0, n)]
    A = iv
    encrypt = AES.new(kek).encrypt
    for j in range(6):
        for i in range(1, n + 1):
            B = encrypt(QUAD.pack(A) + R[i])
            A = QUAD.unpack(B[:8])[0] ^ (n * j + i)
            R[i] = B[8:]
    return QUAD.pack(A) + "".join(R[1:])


def aes_wrap_key_withpad(kek, plaintext):
    iv = 0xA65959A600000000 + len(plaintext)
    plaintext += "\0" * (8 - len(plaintext) % 8)
    return aes_wrap_key(kek, plaintext, iv)


RNG_MAP = {
    'rdrand': rdrand.rdrand_bytes,
    'pycrypto': _pycrypto_rand_bytes,
    'devrandom': _devrandom_read_bytes,
    'devurandom': _devurandom_read_bytes,
}
