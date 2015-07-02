#!/usr/bin/env python2
__author__ = 'Sean Davis <dive@endersgame.net>'
import os
from distutils.core import setup, Extension

RDRAND = Extension('cryptoe.Hardware.RDRAND',
                   include_dirs=[os.path.join(os.getcwd(), 'src', 'include')],
                   sources=['src/rng/rdrand.c',
                            'src/rng/pyrdrand.c'])
shad256_ext = Extension('cryptoe.Hash.SHAd256',
                        include_dirs=[os.path.join(os.getcwd(), 'src', 'include')],
                        sources=['src/hash/SHAd256.c'])

ext_mods = [RDRAND, shad256_ext]

# LNXKeyring_ext is only useful on Linux...
if os.uname()[0] == 'Linux':
    LNXKeyring_ext = Extension('cryptoe.OS.LNXKeyring',
                               sources=['src/secrets/LNXKeyring.c'],
                               libraries=['keyutils', 'bsd'])
    ext_mods.append(LNXKeyring_ext)

setup(
    name='cryptoe',
    author='Sean Davis',
    author_email='cryptoe@endersgame.net',
    version='1.15.0dev',  # see also cryptoe/__init__.py
    url='https://github.com/sdigit/cryptoe/',
    description='Small, easily integrated library for simple cryptography applications, avoiding OpenSSL.',
    packages=[
        'cryptoe',
        'cryptoe.Hash',
        'cryptoe.Random',
        'cryptoe.Hardware',
        'cryptoe.OS',
    ],
    py_modules=[
        'cryptoe.exceptions',
        'cryptoe.utils',
        'cryptoe.KeyMgmt',
        'cryptoe.KeyDB',
        'cryptoe.KeyWrap',
    ],
    ext_modules=ext_mods,
    requires=[
        'Crypto', 'sqlalchemy', 'whirlpool',
    ],
    scripts=['kdb'],
)
