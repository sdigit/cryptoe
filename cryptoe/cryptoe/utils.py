"""
Functions which don't fit better in another module (or are used by several)
"""

import struct
from cryptoe.Hash import SHAd256, whirlpool

YUBIKEY_HMAC_CR_SLOT = 2


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


def pack_integer_le(size, num, signed=False):
    """
    Return the proper struct character for an integer of given size and signedness
    Raises ValueError if an unexpected size is encountered.

    :param size: Size (in bytes)
    :type size: int
    :return: format character for struct.(pack|unpack)
    :rtype: str
    """
    if size not in [1, 2, 4, 8]:
        raise ValueError('size must be 1, 2, 4, or 8')

    types = {
        'S1': 'b', 'U1': 'B',
        'S2': 'h', 'U2': 'H',
        'S4': 'I', 'U4': 'L',
        'S8': 'q', 'U8': 'Q',
    }
    if signed:
        name = 'S' + str(size)
    else:
        name = 'U' + str(size)
    return struct.pack('>' + types[name], num)


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
