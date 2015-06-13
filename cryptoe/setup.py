#!/usr/bin/env python2
import os
from distutils.core import setup, Extension

# Add these once a context object is ready:
# src/cipher/twofish.c
# src/cipher/serpent.c

cryptoe_ext = Extension('cryptoe_ext',
                        include_dirs=[os.path.join(os.getcwd(), 'src', 'include')],
                        sources=['src/rng/rdrand.c',
                                 'src/cryptoe.c'])

setup(
    name='cryptoe',
    author='Sean Davis',
    author_email='cryptoe@endersgame.net',
    version='1.7.1',   # see also cryptoe/__init__.py
    url='https://github.com/sdigit/cryptoe/',
    description='Small, easily integrated library for simple cryptography applications, avoiding OpenSSL.',
    packages=[
        'cryptoe',
        'cryptoe.Random',
    ],
    py_modules=[
        'cryptoe.utils',
    ],
    ext_modules=[
        cryptoe_ext
    ],
    requires=[
        'Crypto', 'hkdf', 'sqlalchemy',
    ]
)
