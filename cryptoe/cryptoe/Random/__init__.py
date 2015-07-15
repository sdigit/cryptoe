__author__ = 'Sean Davis <dive@endersgame.net>'
__all__ = ['new', 'DRBG']

# noinspection PyProtectedMember
from cryptoe.Random import _ParanoidRNG


# noinspection PyUnusedLocal
def new(*args, **kwargs):
    """
    Return a file-like object used for getting random bytes from the Fortuna CSPRNG.
    Entropy input consists of clock_gettime (both CLOCK_REALTIME and CLOCK_MONOTONIC)
    as well as data from the OS-provided /dev/urandom, and (if available) RDRAND.

    A future version will implement CTR_DRBG per NIST SP800-90A such that each instance
    of Fortuna has its own instance of CTR_DRBG to help further mix the entropy input.
    """
    return _ParanoidRNG.new()


def atfork():
    """Call this whenever you call os.fork()"""
    _ParanoidRNG.reinit()


def get_random_bytes(n):
    """Return the specified number of cryptographically-strong random bytes."""
    return _ParanoidRNG.get_random_bytes(n)


_new_funcs = {}


def _DRBG_new(*args):
    # noinspection PyUnresolvedReferences
    from cryptoe.Random import DRBG
    _new_funcs['DRBG'] = _new_funcs['DRBG'] = DRBG.new
    return DRBG.new(*args)


_new_funcs['DRBG'] = _new_funcs['DRBG'] = _DRBG_new
del _DRBG_new
