__author__ = 'Sean Davis <dive@endersgame.net>'
__all__ = ['new']

# noinspection PyProtectedMember
from cryptoe.Random import _ParanoidRNG


# noinspection PyUnusedLocal
def new(*args, **kwargs):
    """
    Return a file-like object that outputs cryptographically random bytes.
    Ignore args and kwargs as they do not matter for this RNG.
    """
    return _ParanoidRNG.new()


def atfork():
    """Call this whenever you call os.fork()"""
    _ParanoidRNG.reinit()


def get_random_bytes(n):
    """Return the specified number of cryptographically-strong random bytes."""
    return _ParanoidRNG.get_random_bytes(n)
