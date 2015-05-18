#!/usr/bin/env python2
from distutils.core import setup, Extension

cryptoe_ext = Extension('cryptoe_ext',
                        sources=['src/rdrand.c',
                                 'src/sha2.c',
                                 'src/hmac_sha2.c',
                                 'src/cryptoe.c'])

setup(name='cryptoe',
      author='Sean Davis',
      author_email='cryptoe@endersgame.net',
      version='1.5.0-dev',
      url='https://github.com/sdigit/cryptoe/',
      description='Small, easily integrated library for simple cryptography applications, avoiding OpenSSL.',
      packages=['cryptoe'],
      ext_modules=[cryptoe_ext], requires=['Crypto'])
