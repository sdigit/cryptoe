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

KernelKeyUtil = Extension('cryptoe.OS.KernelKeyUtil',
                          sources=['src/secrets/KernelKeyUtil.c'],
                          libraries=['keyutils', 'bsd'],
                          extra_compile_args=['-O0', '-g'])
# Once KernelKeyUtil is feature-complete and stable, remove extra_compile_args.
setup(
    name='cryptoe',
    author='Sean Davis',
    author_email='cryptoe@endersgame.net',
    version='1.13.0a',  # see also cryptoe/__init__.py
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
    ext_modules=[
        RDRAND,
        shad256_ext,
        KernelKeyUtil,
    ],
    requires=[
        'Crypto', 'hkdf', 'sqlalchemy', 'whirlpool',
    ],
    scripts=['kdb'],
)
