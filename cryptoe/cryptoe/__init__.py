import struct

__author__ = 'Sean Davis <dive@endersgame.net>'
__all__ = ['utils', 'KeyMgmt', 'KeyWrap', 'KeyDB', 'Hash']
version_info = (1, 9, 1)
__version__ = '.'.join([str(_) for _ in version_info])
DEFAULT_PBKDF2_ITERATIONS = 2 ** 16
MINIMUM_PBKDF2_ITERATIONS = 2 ** 15
YUBIKEY_HMAC_CR_SLOT = 2
QUAD = struct.Struct('>Q')
