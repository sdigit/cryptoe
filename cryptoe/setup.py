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
                        sources=['src/hash/SHAd256.c',
                                 'src/hash/_SHAd256.c'])

ext_mods = [RDRAND, shad256_ext]

if os.uname()[0] in ['Linux', 'NetBSD']:
    oslower = os.uname()[0].lower()
    DRBG = Extension('cryptoe.Random.DRBG',
                     include_dirs=[os.path.join(os.getcwd(), 'src', 'include'),
                                   os.path.join(os.getcwd(), 'src', 'rng')],
                     sources=[
                         'src/rng/nist_ctr_drbg/nist_ctr_drbg.c',
                         'src/rng/nist_ctr_drbg/rijndael-alg-fst.c',
                         'src/rng/nist_ctr_drbg/rijndael-api-fst.c',
                         'src/rng/nist_ctr_drbg/rijndael.c',
                         'src/hash/SHAd256.c',
                         'src/rng/aes_ctr_drbg.c',
                         'src/rng/DRBG.c',
                     ])
    DRBG.sources.append('src/os/' + oslower + '.c')
    if oslower == 'linux':
        DRBG.libraries.append('bsd')
    ext_mods.append(DRBG)

if os.uname()[0] == 'Linux':
    LNXKeyring_ext = Extension('cryptoe.OS.LNXKeyring',
                               sources=['src/secrets/LNXKeyring.c'],
                               libraries=['keyutils', 'bsd'])
    ext_mods.append(LNXKeyring_ext)


setup(
    name='cryptoe',
    author='Sean Davis',
    author_email='cryptoe@endersgame.net',
    version='2.0.0dev',  # see also cryptoe/__init__.py
    url='https://github.com/sdigit/cryptoe/',
    description='Small, easily integrated library for simple cryptography applications, avoiding OpenSSL.',
    packages=[
        'cryptoe',
        'cryptoe.Hash',
        'cryptoe.OS',
        'cryptoe.Random',
        'cryptoe.Hardware',
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
        'pycrypto', 'sqlalchemy', 'whirlpool',
    ],
    scripts=['kdb'],
)
