"""
This script compares the output of Crypto.Hash.SHA(256,384,512) and cryptoe_ext.SHA(256,384,512) in order to ensure that
the cryptoe_ext implementations are functioning as expected.
"""

__author__ = 'Sean Davis <dive@endersgame.net>'

import cryptoe_ext

import Crypto.Hash.SHA256
import Crypto.Hash.SHA384
import Crypto.Hash.SHA512


class DigestWrapper(object):
    """
    Wrapper so we can use PEP 247 compliant hash functions, or something else.
    """

    def __init__(self, name, thing):
        """
        A simple wrapper around any callable function, storing a name.
        :rtype : DigestWrapper
        """
        self.name = name
        self.thing = thing

    def __repr__(self):
        return '<' + self.__class__.__name__ + ' --> ' + self.thing.__name__ + '>'

    def digest(self, msg):
        """
        Run the configured hash function and return its result
        :param msg: message to hash
        """
        if callable(self.thing):
            return self.thing(msg)
        else:
            thing_obj = self.thing.new()
            thing_obj.update(msg)
            retval = thing_obj.digest()
            return retval


test_funcs = {
    'SHA256': {
        'OpenSSL SHA-256': Crypto.Hash.SHA256,
        'Cryptoe SHA-256': cryptoe_ext.SHA256,
    },
    'SHA384': {
        'OpenSSL SHA-384': Crypto.Hash.SHA384,
        'Cryptoe SHA-384': cryptoe_ext.SHA384,
    },
    'SHA512': {
        'OpenSSL SHA-512': Crypto.Hash.SHA512,
        'Cryptoe SHA-512': cryptoe_ext.SHA512,
    },
}


def bytes_as_str(string):
    """
    :type string: str
    """
    return ' '.join(['%02x' % x for x in bytearray(string)])


def resmap(v):
    if v == 1:
        return 'PASS'
    elif v > 1:
        return 'MISMATCH DETECTED'
    elif v < 1:
        return 'UNEXPECTED LENGTH'


if __name__ == '__main__':
    results = {}
    fd = {f: [] for f in test_funcs}
    test_messages = [
        '',
        'one two three four',
        'This string is longer than the block size of SHA512 (1024 bits) can accommodate. '
        'It will require the algorithm to split the message.',
    ]
    print(fd)
    for m in test_messages:
        for f in fd:
            rv = []
            for h in test_funcs[f]:
                dw = DigestWrapper(name=h, thing=test_funcs[f][h])
                rv.append(dw.digest(m))
            rvl = len(rv)
            rv = list(set(rv))
            print('{0:s} {1:d} {2:d} {3:s}'.format(f, rvl, len(rv), resmap(len(rv))))
