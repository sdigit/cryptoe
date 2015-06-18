# -*- coding: utf-8 -*-
#
#  Random/_ParanoidRNG.py : A user-friendly random number generator
#
# Written in 2008 by Dwayne C. Litzenberger <dlitz@dlitz.net>
#
# ===================================================================
# The contents of this file are dedicated to the public domain.  To
# the extent that dedication to the public domain is not available,
# everyone is granted a worldwide, perpetual, royalty-free,
# non-exclusive license to exercise all rights associated with the
# contents of this file for any purpose whatsoever.
# No rights are reserved.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ===================================================================
import cryptoe_ext
import os
import threading
import struct
import time

from math import floor, ceil
from Crypto.Hash import HMAC, SHA512
from Crypto.Random import OSRNG

from Crypto.Random.Fortuna import FortunaAccumulator
from cryptoe.Hash import SHAd256

RDRAND_SUPPORTED = 0


class _EntropySource(object):
    def __init__(self, accumulator, src_num):
        self._fortuna = accumulator
        self._src_num = src_num
        self._pool_num = 0

    def feed(self, data):
        self._fortuna.add_random_event(self._src_num, self._pool_num, data)
        self._pool_num = (self._pool_num + 1) & 31


class _EntropyCollector(object):
    def __init__(self, accumulator):
        self.fancy = 1
        self._hmac = HMAC.new(key=cryptoe_ext.rdrand_bytes(32), digestmod=SHAd256)
        self._osrng = OSRNG.new()
        es_num = 255
        self._osrng_es = _EntropySource(accumulator, es_num)
        es_num -= 1
        if RDRAND_SUPPORTED:
            cryptoe_ext.rdrand_64(1024)
            self._rdrand_es = _EntropySource(accumulator, es_num)
            es_num -= 1

        self._time_es = _EntropySource(accumulator, es_num)
        es_num -= 1
        self._clock_es = _EntropySource(accumulator, es_num)
        del es_num

    def reinit(self):

        if RDRAND_SUPPORTED:
            # force RDRAND to reseed
            cryptoe_ext.rdrand_64(1024)
            self._hmac = HMAC.new(key=cryptoe_ext.rdrand_bytes(32), digestmod=SHAd256)
            for i in range(2):
                # force RDRAND to reseed
                block = cryptoe_ext.rdrand_bytes(32 * 32)
                # force RDRAND to reseed
                for p in range(32):
                    self._rdrand_es.feed(block[p * 32:(p + 1) * 32])
                block = None
                del block
            # Add 256 bits to each of the 32 pools, twice, from OSRNG. Force RDRAND reseed as it is used
            # by the linux kernel PRNG.
            cryptoe_ext.rdrand_64(1024)
        else:
            self._hmac = HMAC.new(key=self._osrng.read(32), digestmod=SHAd256)
        for i in range(2):
            block = self._osrng.read(32 * 32)
            for p in range(32):
                self._osrng_es.feed(block[p * 32:(p + 1) * 32])
            block = None
            del block
        self._osrng.flush()

    def collect(self):
        # Collect 64 bits of entropy from the OS and feed it to Fortuna
        self._osrng_es.feed(self._osrng.read(8))  # + 64 bits
        # hash the fractional part of time.time()
        t = time.time()
        self._hmac.update(struct.pack("@L", int(2 ** 30 * (t - floor(t)))))
        self._hmac.update(struct.pack("@L", int(ceil(t))))
        self._time_es.feed(self._hmac.digest()[:32])  # + 256 bits
        #  and the fractional part of time.clock()
        t = time.clock()
        self._hmac.update(struct.pack("@L", int(2 ** 30 * (t - floor(t)))))
        self._hmac.update(struct.pack("@L", int(ceil(t))))
        self._clock_es.feed(self._hmac.digest()[:32])  # + 256 bits
        t = None
        h = None
        del t
        del h
        if RDRAND_SUPPORTED:
            # Feed Fortuna four 64bit RDRANDs, conditioned by SHA512
            cryptoe_ext.rdrand_64(1024)
            r = cryptoe_ext.rdrand_bytes(64)
            r = SHA512.new(r).digest()[:32]
            self._rdrand_es.feed(r)
            r = None
            del r


class _ParanoidRNG(object):
    def __init__(self):
        self.closed = False
        self._fa = FortunaAccumulator.FortunaAccumulator()
        self._ec = _EntropyCollector(self._fa)
        self._pid = -1
        self._osrng = None
        self.reinit()

    def reinit(self):
        """Initialize the random number generator and seed it with entropy from
        the operating system.
        :type self: _ParanoidRNG
        """

        # Save the pid (helps ensure that Crypto.Random.atfork() gets called)
        self._pid = os.getpid()

        # Collect entropy from the operating system and feed it to
        # FortunaAccumulator
        self._ec.reinit()

        # Override FortunaAccumulator's 100ms minimum re-seed interval.  This
        # is necessary to avoid a race condition between this function and
        # self.read(), which that can otherwise cause forked child processes to
        # produce identical output.  (e.g. CVE-2013-1445)
        #
        # Note that if this function can be called frequently by an attacker,
        # (and if the bits from OSRNG are insufficiently random) it will weaken
        # Fortuna's ability to resist a state compromise extension attack.

        # noinspection PyProtectedMember
        self._fa._forget_last_reseed()

    def close(self):
        """
        Close the OS RNG and lose the reference to the Fortuna accumulator

        :type self: _ParanoidRNG
        """
        self.closed = True
        self._osrng = None
        self._fa = None

    def flush(self):
        pass

    def read(self, n):
        """Return N bytes from the RNG."""
        if self.closed:
            raise ValueError("I/O operation on closed file")
        if not isinstance(n, (long, int)):
            raise TypeError("an integer is required")
        if n < 0:
            raise ValueError("cannot read to end of infinite stream")

        # Collect some entropy and feed it to Fortuna
        self._ec.collect()

        # Ask Fortuna to generate some bytes
        retval = self._fa.random_data(n)

        # Check that we haven't forked in the meantime.  (If we have, we don't
        # want to use the data, because it might have been duplicated in the
        # parent process.
        self._check_pid()

        # Return the random data.
        return retval

    def _check_pid(self):
        # Lame fork detection to remind developers to invoke Random.atfork()
        # after every call to os.fork().  Note that this check is not reliable,
        # since process IDs can be reused on most operating systems.
        #
        # You need to do Random.atfork() in the child process after every call
        # to os.fork() to avoid reusing PRNG state.  If you want to avoid
        # leaking PRNG state to child processes (for example, if you are using
        # os.setuid()) then you should also invoke Random.atfork() in the
        # *parent* process.
        if os.getpid() != self._pid:
            raise AssertionError("PID check failed. RNG must be re-initialized after fork(). Hint: Try Random.atfork()")


class _LockingParanoidRNG(_ParanoidRNG):
    def __init__(self):
        self._lock = threading.Lock()
        _ParanoidRNG.__init__(self)

    def close(self):
        self._lock.acquire()
        try:
            return _ParanoidRNG.close(self)
        finally:
            self._lock.release()

    def reinit(self):
        self._lock.acquire()
        try:
            return _ParanoidRNG.reinit(self)
        finally:
            self._lock.release()

    def read(self, nbytes):
        self._lock.acquire()
        try:
            return _ParanoidRNG.read(self, nbytes)
        finally:
            self._lock.release()


class RNGFile(object):
    def __init__(self, singleton):
        self.closed = False
        self._singleton = singleton

    # PEP 343: Support for the "with" statement
    def __enter__(self):
        """PEP 343 support"""

    def __exit__(self):
        """PEP 343 support"""
        self.close()

    def close(self):
        # Don't actually close the singleton, just close this RNGFile instance.
        self.closed = True
        self._singleton = None

    def read(self, nbytes):
        if self.closed:
            raise ValueError("I/O operation on closed file")
        return self._singleton.read(nbytes)

    def flush(self):
        if self.closed:
            raise ValueError("I/O operation on closed file")


_singleton_lock = threading.Lock()
_singleton = None


def _get_singleton():
    global _singleton
    _singleton_lock.acquire()
    try:
        if _singleton is None:
            _singleton = _LockingParanoidRNG()
        return _singleton
    finally:
        _singleton_lock.release()


def new():
    """
    Instantiate and return a new (hopefully safe) locking RNG.

    :rtype : _LockingParanoidRNG
    """
    return RNGFile(_get_singleton())


def reinit():
    _get_singleton().reinit()


def get_random_bytes(n):
    """Return the specified number of cryptographically-strong random bytes."""
    return _get_singleton().read(n)


def check_for_rdrand():
    global RDRAND_SUPPORTED
    try:
        from cryptoe_ext import rdrand_64

        rdrand_64(1)
    except MemoryError:
        RDRAND_SUPPORTED = False
    RDRAND_SUPPORTED = True


check_for_rdrand()
