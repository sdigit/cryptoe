import struct

__author__ = 'Sean Davis <dive@endersgame.net>'
__all__ = ['utils']
__version__ = '1.5.3a0'
version_info = (1, 5, 3, 'alpha', 0)

DEFAULT_PBKDF2_ITERATIONS = 20000
QUAD = struct.Struct('>Q')
