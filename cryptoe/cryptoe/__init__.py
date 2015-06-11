import struct

__author__ = 'Sean Davis <dive@endersgame.net>'
__all__ = ['utils', 'KeyMgmt', 'KeyWrap', 'KeyDB']
__version__ = '1.6.1a'
version_info = (1, 6, 1,'a')

DEFAULT_PBKDF2_ITERATIONS = 20000
QUAD = struct.Struct('>Q')
