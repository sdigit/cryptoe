__all__ = ['SHAd256', 'whirlpool']

import whirlpool


def new(algo, *args):
    """Initialize a new hash object.

    The first argument to this function may be an algorithm name or another
    hash object.

    This function has significant overhead.  It's recommended that you instead
    import and use the individual hash modules directly.
    """

    # Try just invoking algo.new()
    # We do this first so that this is the fastest.
    try:
        new_func = algo.new
    except AttributeError:
        pass
    else:
        return new_func(*args)

    # Try getting the algorithm name.
    if isinstance(algo, str):
        name = algo
    else:
        try:
            name = algo.name
        except AttributeError:
            raise ValueError("unsupported hash type %r" % (algo,))

    # Got the name.  Let's see if we have a PyCrypto implementation.
    try:
        new_func = _new_funcs[name]
    # if not, fail, because hashlib relies on openssl. do not use it.
    except KeyError:
        raise ValueError("unsupported hash type %s" % (name,))
    else:
        # We have a PyCrypto implementation.  Instantiate it.
        return new_func(*args)

# This dict originally gets the following _*_new methods, but its members get
# replaced with the real new() methods of the various hash modules as they are
# used.  We do it without locks to improve performance, which is safe in
# CPython because dict access is atomic in CPython.  This might break PyPI.
_new_funcs = {}


def _shad256_new(*args):
    from cryptoe.Hash import SHAd256

    _new_funcs['SHAd256'] = _new_funcs['shad256'] = SHAd256.new
    return SHAd256.new(*args)


_new_funcs['SHAd256'] = _new_funcs['shad256'] = _shad256_new
del _shad256_new


def _whirlpool_new(*args):
    import whirlpool

    _new_funcs['whirlpool'] = _new_funcs['whirlpool'] = whirlpool.new
    return whirlpool.new(*args)


_new_funcs['whirlpool'] = _new_funcs['whirlpool'] = _whirlpool_new
del _whirlpool_new
