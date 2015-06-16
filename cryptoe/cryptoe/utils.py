"""
Centralize all cryptography primitives (as well as data conversion routines) that are commonly needed, in order to
ensure that implementations differ as little as possible.

Where non-cryptoe code is used (eg. pycrypto), I have endeavored to verify that the implementation being referenced is
compliant with the relevant standards (NIST or RFC), however can only vouch for the versions audited at the time this
was written.

For a complete list of which documents the cryptoe package implements in whole or in part, see the REFS file in the
master cryptoe directory.
"""
from cryptoe.KeyMgmt import SHAd256_HEX

__author__ = 'Sean Davis <dive@endersgame.net>'

import struct

from Crypto.Util import Counter
from Crypto.Cipher import AES

from cryptoe import Random, YUBIKEY_HMAC_CR_SLOT


def pad(what, size):
    if len(what) > size:
        raise ValueError('length exceeds desired padded length')
    elif len(what) == size:
        return what
    wlen = len(what)
    plen = size - wlen
    out = struct.pack('<s', what)
    pad_bytes = [struct.pack('B', _) for _ in xrange(0, plen)]
    out += ''.join(pad_bytes)
    del pad_bytes
    del wlen
    del plen
    return out


def long2ba(val):
    """
    Convert a long integer into a bytearray

    :param val: a long integer
    :return: bytearray
    """
    b = bytearray()
    n = abs(val)
    while n > 0:
        b += struct.pack('<B', n % 256)
        n >>= 8
    return bytearray(reversed(b))


def ba2long(val):
    """
    Convert a bytearray into a long integer

    :param val: a bytearray
    :return: long
    """
    n = 0
    for b in val:
        n <<= 8
        if type(b) == int:
            n += b
        elif type(b) == str:
            n += ord(b)
    return long(n)


def rndbytes(sz):
    """
    Return sz random bytes
    :type sz: int
    :param sz: how many bytes
    :return: bytes
    """
    return _rng.read(sz)


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


def yubikey_passphrase_cr(passphrase):
    try:
        import yubico
    except ImportError:
        yubico = None
    if not yubico:
        del yubico
        print('[YubiKey] yubico module not found. using passphrase directly.')
        return passphrase
    try:
        yubikey = yubico.find_yubikey()
    except yubico.yubikey.YubiKeyError:
        print('[YubiKey] yubikey not found. using passphrase directly.')
        return passphrase
    if yubikey:
        challenge = SHAd256_HEX(passphrase)
        print('[YubiKey] Sending challenge')
        try:
            response = yubikey.challenge_response(challenge, slot=KEYDB_YUBIKEY_CR_SLOT)
        except yubico.yubikey.YubiKeyTimeout:
            print('[YubiKey] timeout waiting for response to challenge.')
            return passphrase
        passphrase = response
    return passphrase


_rng = Random.new()
