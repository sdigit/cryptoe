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

import struct
from cryptoe.Hash import SHAd256, whirlpool
from cryptoe import YUBIKEY_HMAC_CR_SLOT


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


def pad(what, size):
    """
    PKCS#7 padding

    :param what: input data
    :param size: size desired after padding
    :return: padded data
    """
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


def yubikey_passphrase_cr(passphrase):
    """
    This function:
     Takes an input passphrase
     generates the SHAd256 hash of it
     sends that hash to a Yubikey configured for HMAC-SHA1 on slot 2
     computes the whirlpool hash of the HMAC-SHA1 response received from the Yubikey
     returns the whirlpool hash
    :param passphrase: passphrase (plaintext)
    :type passphrase: str
    :return: whirlpool digest (hex)
    :rtype: str
    """
    try:
        import yubico
    except ImportError:
        yubico = None
    if not yubico:
        del yubico
        return passphrase
    try:
        yubikey = yubico.find_yubikey()
    except yubico.yubikey.YubiKeyError:
        return passphrase
    if yubikey:
        challenge = SHAd256.new(passphrase).hexdigest()
        print('[YubiKey] Sending challenge')
        try:
            response = yubikey.challenge_response(challenge, slot=YUBIKEY_HMAC_CR_SLOT)
            print('[YubiKey] Got response')
        except yubico.yubikey.YubiKeyTimeout:
            print('[YubiKey] Timeout. Not using Yubikey.')
            return passphrase
        passphrase = whirlpool.new(response).hexdigest()
    return passphrase
