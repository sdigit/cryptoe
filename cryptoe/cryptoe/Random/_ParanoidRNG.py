# PUBLIC DOMAIN
import os
import threading
from collections import OrderedDict

from Crypto.Random import OSRNG
from Crypto.Random.Fortuna import FortunaAccumulator
from cryptoe.utils import pack_integer_le

from time import clock, time
from math import floor, ceil

SUPPORTED_SYSTEMS = ['Linux', 'NetBSD']


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
        self._nsrc = 255
        self._srcs = OrderedDict()
        self._osrng = OSRNG.new()
        self._rng_lock = threading.Lock()
        self._src_lock = threading.Lock()
        self.add_source('osrng', accumulator)
        self.add_source('time', accumulator)
        self.add_source('clock', accumulator)
        self._counters = {}
        if os.uname()[0] in ['NetBSD', 'Linux']:
            # noinspection PyUnresolvedReferences
            from cryptoe.Random import DRBG
            for x in xrange(0, 32):
                ctr = 'ctr_drbg' + str(x)
                self._counters[ctr] = DRBG.new()
                self.add_source(ctr, accumulator)
        try:
            # noinspection PyUnresolvedReferences
            from cryptoe.Hardware import RDRAND
            self._rdrand = RDRAND
        except ImportError:
            """Nothing yet."""

    @property
    def using_rdrand(self):
        with self._src_lock:
            ret = 'rdrand' in self._srcs
        return ret

    def add_source(self, name, accumulator):
        """
        Adds a new entropy collector to this object.

        :param name: Name of the new entropy source
        :param accumulator: FortunaAccumulator which should use this source
        :raise OverflowError: source is already in use
        """
        if self._nsrc == 0:
            raise RuntimeError('Cannot add another entropy source')
        if name in self._srcs:
            raise NameError('entropy source "%s" already exists!' % str(name))
        with self._src_lock:
            self._srcs[name] = _EntropySource(accumulator, self._nsrc)
            self._nsrc -= 1

    def collect(self):
        """
        Collect entropy from available sources
        """
        self._srcs['osrng'].feed(self._osrng.read(8))
        self._osrng.flush()
        if self.using_rdrand:
            self._srcs['rdrand'].feed(self._rdrand.rdrand_bytes(32))
            self._rdrand.rdrand_64(1024)
        tm = time()
        self._srcs['time'].feed(pack_integer_le(4, int(2 ** 30 * (tm - floor(tm)))))
        self._srcs['time'].feed(pack_integer_le(4, int(ceil(tm))))
        ck = clock()
        self._srcs['clock'].feed(pack_integer_le(4, int(2 ** 30 * (ck - floor(ck)))))
        if len(self._counters) > 0:
            for ctr in self._counters:
                self._srcs[ctr].feed(self._counters[ctr].read(16))

    def reinit(self):
        """
        Reinitialize the collector.
        """
        # Add 256 bits to each of the 32 pools, twice, from OSRNG
        seed_len = 32 * 32
        for i in range(2):
            block = self._osrng.read(1024)
            for p in range(32):
                with self._src_lock:
                    self._srcs['osrng'].feed(block[p * 32:(p + 1) * 32])
            block = None
            del block
        self._osrng.flush()

        if self.using_rdrand:
            # Add 256 bits to each of the 32 pools, twice, from RDRAND
            for i in range(2):
                self._rdrand.rdrand_64(1024)
                block = self._rdrand.rdrand_bytes(seed_len)
                for p in range(32):
                    self._srcs['rdrand'].feed(block[p * 32:(p + 1) * 32])
                block = None
                del block
            self._rdrand.rdrand_64(1024)
        self.collect()


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
        self.closed = True
        """
        Close the OS RNG and lose the reference to the Fortuna accumulator

        :type self: _ParanoidRNG
        """
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
