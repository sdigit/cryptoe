import struct

__author__ = 'Sean Davis <dive@endersgame.net>'

from Crypto.Cipher import AES


class KeyWrapAlgorithm(object):
    def __init__(self):
        self._algo_name = ''
        self._cipher_name = 'AES'

    def __repr__(self):
        return '<KeyWrapAlgorithm[' + str(self._algo_name) + ',' + str(self._cipher_name) + '>'


class KW(KeyWrapAlgorithm):
    @staticmethod
    def wrap(kek, key):
        return wrap_key(kek, key)

    @staticmethod
    def unwrap(kek, wrapped):
        return unwrap_key(kek, wrapped)


class KWP(KeyWrapAlgorithm):
    @staticmethod
    def wrap(kek, key):
        return wrap_key_withpad(kek, key)

    @staticmethod
    def unwrap(kek, wrapped):
        return unwrap_key_withpad(kek, wrapped)


def unwrap_key_and_iv(kek, wrapped):
    n = len(wrapped) / 8 - 1
    r = [None] + [wrapped[i * 8:i * 8 + 8] for i in range(1, n + 1)]
    QUAD = struct.Struct('>Q')
    a = QUAD.unpack(wrapped[:8])[0]
    decrypt = AES.new(kek).decrypt
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            # noinspection PyTypeChecker
            ciphertext = QUAD.pack(a ^ (n * j + i)) + r[i]
            cb = decrypt(ciphertext)
            a = QUAD.unpack(cb[:8])[0]
            r[i] = cb[8:]
    # noinspection PyTypeChecker
    return "".join(r[1:]), a


def unwrap_key(kek, wrapped, iv=0xa6a6a6a6a6a6a6a6):
    key, key_iv = unwrap_key_and_iv(kek, wrapped)
    if key_iv != iv:
        raise ValueError("Integrity Check Failed: " + hex(key_iv) + " (expected " + hex(iv) + ")")
    return key


def unwrap_key_withpad(kek, wrapped):
    key, key_iv = unwrap_key_and_iv(kek, wrapped)
    key_iv = "{0:016X}".format(key_iv)
    if key_iv[:8] != "A65959A6":
        raise ValueError("Integrity Check Failed: " + key_iv[:8] + " (expected A65959A6)")
    key_len = int(key_iv[8:], 16)
    return key[:key_len]


def wrap_key(kek, plaintext, iv=0xa6a6a6a6a6a6a6a6):
    n = len(plaintext) / 8
    r = [None] + [plaintext[i * 8:i * 8 + 8] for i in range(0, n)]
    a = iv
    encrypt = AES.new(kek).encrypt
    QUAD = struct.Struct('>Q')
    for j in range(6):
        for i in range(1, n + 1):
            # noinspection PyTypeChecker
            cb = encrypt(QUAD.pack(a) + r[i])
            a = QUAD.unpack(cb[:8])[0] ^ (n * j + i)
            r[i] = cb[8:]
    # noinspection PyTypeChecker
    return QUAD.pack(a) + "".join(r[1:])


def wrap_key_withpad(kek, plaintext):
    iv = 0xA65959A600000000 + len(plaintext)
    plaintext += "\0" * (8 - len(plaintext) % 8)
    return wrap_key(kek, plaintext, iv)
