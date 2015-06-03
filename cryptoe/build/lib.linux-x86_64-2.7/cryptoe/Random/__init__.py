__author__ = 'dive'
__all__ = ['new']

from cryptoe.Random import _ParanoidRNG

def new(*args, **kwargs):
    """Return a file-like object that outputs cryptographically random bytes."""
    return _ParanoidRNG.new(*args, **kwargs)

def atfork():
    """Call this whenever you call os.fork()"""
    _ParanoidRNG.reinit()

def get_random_bytes(n):
    """Return the specified number of cryptographically-strong random bytes."""
    return _ParanoidRNG.get_random_bytes(n)
