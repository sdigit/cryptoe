def check_type(v, t):
    """
    Make sure value v is of type t
    Otherwise raise IndexError

    :param v: value to check
    :type v: object
    :param t: type expected
    :type t: type
    :return: Truth value
    :rtype: bool
    """
    if not isinstance(v, t):
        raise TypeError('Expected an object of type {0:s}, got {1:s}'.format(repr(t), type(v)))
    return True


def check_range(v, start, end):
    """
    Make sure an integer is between start and end (inclusive)
    Otherwise raise IndexError

    :param v: integer value
    :type v: int
    :param start: min value
    :type start: int
    :param end: max value
    :type end: int
    :return: Truth value
    :rtype: None
    """
    check_type(v, int)
    check_type(start, int)
    check_type(end, int)
    if not start <= v <= end:
        raise IndexError('Invalid range')
    return True


def check_value(v, t, ok):
    """
    Make sure a value v is in an iterable of valid values
    :param v: value
    :param t: type (for call to check_type)
    :type t: type
    :param ok:
    :type ok: list
    :return: true if check passes; else raise an exception
    :rtype: bool
    """
    check_type(ok, list)
    check_type(v, t)
    if len(ok) < 1:
        raise IndexError('must specify at least one valid value')
    if v not in ok:
        raise ValueError('value is not in acceptable list')
    return True


def check_len(v, t, l):
    """
    Make sure the length of v is equal to l
    :param v: value
    :type v:
    :param t: type v should be
    :param l: int
    :type l: int
    :return: true if check passes, else raise an exception
    :rtype: bool
    """
    check_type(v, t)
    check_type(t, type)
    check_type(l, t)
