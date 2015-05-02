"""
Centralize all cryptography primitives (as well as data conversion routines) that are commonly needed, in order to
ensure that implementations differ as little as possible.

Where non-cryptoe code is used (eg. pycrypto), I have endeavored to verify that the implementation being referenced is
compliant with the relevant standards (NIST or RFC), however can only vouch for the versions audited at the time this
was written.

For a complete list of which documents the cryptoe package implements in whole or in part, see the REFS file in the
master cryptoe directory.
"""

__author__ = 'Sean Davis <dive@endersgame.net>'

from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util import Counter, RFC1751
from Crypto.Hash import HMAC, SHA256
from Crypto.Cipher import AES
import math
import struct
import cryptoe_ext

DEFAULT_PBKDF2_ITERATIONS = 20000
QUAD = struct.Struct('>Q')


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


def rndbytes(sz):
    """
    Return sz random bytes
    :param sz: how many bytes
    :return: bytes
    """
    return cryptoe_ext.rdrand_bytes(sz)


def __pack_for_kdf(string):
    return struct.pack('>' + ('s' * len(string)), string)


def __prf(k, s):
    """
    This provides the Pseudo-Random Function for CTR-KDF.

    :param k: Key
    :param s: Data
    :return:
    """
    h = HMAC.new(k, digestmod=SHA256)
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
    """
    AES256 in CTR mode (Encrypt)

    :param k: Key
    :param msg: Plaintext
    :return: Ciphertext
    """
    ctr = Counter.new(128)
    aes = AES.new(k, AES.MODE_CTR, counter=ctr)
    ct = aes.encrypt(msg)
    del ctr
    del aes
    return ct


def ctr_dec(k, msg):
    """
    AES256-CTR (Decrypt)

    :param k: Key
    :param msg: Ciphertext
    :return: Plaintext
    """
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


def key128_to_str(key):
    """
    Convert 128-bit key (bytes or int) to RFC1751 format
    :param key: bytes or int containing 128 bits to be converted to words
    :rtype: str
    :return: RFC1751 words
    """
    if isinstance(key, int):
        return RFC1751.key_to_english(bytes(key))
    elif isinstance(key, bytes):
        return RFC1751.key_to_english(key)
    else:
        raise TypeError('expected int or bytes')


def str_to_key128(words):
    """
    Convert RFC1751 encoded key to bytes
    :param words: the words
    :type words: str
    :return: bytes
    :rtype: bytes
    """
    if not isinstance(words, str):
        raise TypeError('expected string')
    return RFC1751.english_to_key(words)


def pw2key(pw, salt=None, digest=SHA256):
    """
    This function is a wrapper for purposes of convenience around Crypto.Protocol.KDF.PBKDF2
    PBKDF2 per NIST SP800-132 is used with HMAC-SHA256 as a default. Salt and an alternate digest can be specified.
    A list containing the derived key and the salt is returned.

    :param pw: password
    :param salt: salt for PBKDF
    :param digest:
    :return: {'key': key, 'salt': salt}
    :rtype: dict
    """
    lprf = lambda x, y: HMAC.new(x, msg=y, digestmod=digest).digest()
    if not salt:
        salt = rndbytes(32)
    return [PBKDF2(pw, salt, dkLen=32, prf=lprf, count=DEFAULT_PBKDF2_ITERATIONS), salt]
