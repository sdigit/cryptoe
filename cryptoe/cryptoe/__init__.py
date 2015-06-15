import struct

__author__ = 'Sean Davis <dive@endersgame.net>'
__all__ = ['utils', 'KeyMgmt', 'KeyWrap', 'KeyDB', 'Hash']
__version__ = '1.7.1'
version_info = (1, 7, 1)

DEFAULT_PBKDF2_ITERATIONS = 20000
QUAD = struct.Struct('>Q')
