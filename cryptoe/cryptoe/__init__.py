import struct

__author__ = 'Sean Davis <dive@endersgame.net>'
__all__ = ['Random', 'utils', 'KeyMgmt', 'KeyWrap', 'KeyDB', 'Hash', 'Hardware']
version_info = (1, 14, 0)
__version__ = '1.14.0'
DEFAULT_PBKDF2_ITERATIONS = 2 ** 16
MINIMUM_PBKDF2_ITERATIONS = 2 ** 15
YUBIKEY_HMAC_CR_SLOT = 2
QUAD = struct.Struct('>Q')
