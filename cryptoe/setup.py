#!/usr/bin/env python2
from distutils.core import setup, Extension

rdrand = Extension('rdrand',
                   sources = ['src/rdrand.c',
                              'src/pyrdrand.c'])


setup(name='cryptoe',
      author='Sean Davis',
      author_email='cryptoe@endersgame.net',
      version='1.0a',
      url='https://github.com/sdigit/cryptoe/',
      description='Functions to get random numbers from Intel(r) RDRAND',
      packages = ['cryptoe'],
      ext_modules = [rdrand], requires=['Crypto'])
