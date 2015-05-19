#!/usr/bin/env python2
from distutils.core import setup, Extension
import os

cryptoe_ext = Extension('cryptoe_ext',
                        include_dirs=[os.path.join(os.getcwd(),'src','include')],
                        sources=['src/rng/rdrand.c',
                                 'src/hash/sha2.c',
                                 'src/mac/hmac_sha2.c',
                                 'src/cipher/twofish.c',
                                 'src/cipher/serpent.c',
                                 'src/cryptoe.c'])

setup(name='cryptoe',
      author='Sean Davis',
      author_email='cryptoe@endersgame.net',
      version='1.5.1-wip',
      url='https://github.com/sdigit/cryptoe/',
      description='Small, easily integrated library for simple cryptography applications, avoiding OpenSSL.',
      packages=['cryptoe'],
      ext_modules=[cryptoe_ext], requires=['Crypto'])
