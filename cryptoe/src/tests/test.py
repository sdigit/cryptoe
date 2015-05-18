"""
This script compares the output of Crypto.Hash.SHA(256,384,512) and cryptoe_ext.SHA(256,384,512) in order to ensure that
the cryptoe_ext implementations are functioning as expected.
"""

__author__ = 'Sean Davis <dive@endersgame.net>'

import cryptoe_ext

from collections import OrderedDict

import Crypto.Hash.HMAC
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
        :type msg: str
        :rtype: str
        """
        if callable(self.thing):
            return self.thing(msg)
        else:
            thing_obj = self.thing.new()
            thing_obj.update(msg)
            retval = thing_obj.digest()
            return retval


class HMACWrapper(object):
    """
    Wrapper for PEP 247 HMAC functions or cryptoe_ext HMAC functions
    """

    def __init__(self, name, thing, arg):
        """
        :rtype : HMACWrapper
        :param name:
        :param thing:
        :param arg:
        """
        self.name = name
        self.thing = thing
        self.arg = arg

    def __repr__(self):
        return '<' + self.__class__.__name__ + ' --> ' + self.thing.__name__ + '>'

    def digest(self, m, k='', maclen=0):
        """
        HMAC(key,msg) -> return
        :type m: str
        :type k: str
        :type maclen: int
        :rtype: str
        """
        if callable(self.thing):
            try:
                return self.thing(k, m, maclen)
            except MemoryError:
                return -1
        else:
            hmac = Crypto.Hash.HMAC.new(key=k, digestmod=self.thing)
            hmac.update(m)
            retval = hmac.digest()
            return retval


test_messages = [
    '',
    'one two three four',
    'This string is longer than the block size of SHA512 (1024 bits) can accommodate. '
    'It will require the algorithm to split the message.',
]

digest_test_map = {
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


def resmap(v):
    if v == 1:
        return 'PASS'
    elif 0 < v or v > 1:
        return 'FAIL'


def cryptoe_vs_openssl_digest():
    """
    Verify that our digest functions return identical values to OpenSSL.

    :return: None
    :rtype: NoneType
    """
    fd = {f: [] for f in digest_test_map}
    for m in test_messages:
        for f in fd:
            rv = []
            for h in digest_test_map[f]:
                dw = DigestWrapper(name=h, thing=digest_test_map[f][h])
                rv.append(dw.digest(m))
            rvl = len(rv)
            rv = list(set(rv))
            print('{0:s} {1:s}'.format(f, resmap(len(rv))))


def cryptoe_vs_openssl_hmac():
    """
    Verify that simple HMAC operation returns identical values to OpenSSL.

    :return: None
    :rtype: NoneType
    """
    hmac_test_map = OrderedDict()
    hmac_test_map['SHA256'] = {
        'len': 256,
        'keys': [
            cryptoe_ext.rdrand_bytes(16),
            cryptoe_ext.rdrand_bytes(32),
            cryptoe_ext.rdrand_bytes(48),
        ],
        'funcs': {
            'OpenSSL HMAC-SHA-256': Crypto.Hash.SHA256,
            'Cryptoe HMAC-SHA-256': cryptoe_ext.HMAC_SHA256,
        },
    }
    hmac_test_map['SHA384'] = {
        'len': 384,
        'keys': [
            cryptoe_ext.rdrand_bytes(32),
            cryptoe_ext.rdrand_bytes(48),
            cryptoe_ext.rdrand_bytes(64),
        ],
        'funcs': {
            'OpenSSL HMAC-SHA-384': Crypto.Hash.SHA384,
            'Cryptoe HMAC-SHA-384': cryptoe_ext.HMAC_SHA384,
        },
    }
    hmac_test_map['SHA512'] = {
        'len': 512,
        'keys': [
            cryptoe_ext.rdrand_bytes(48),
            cryptoe_ext.rdrand_bytes(64),
            cryptoe_ext.rdrand_bytes(72),
        ],
        'funcs': {
            'OpenSSL HMAC-SHA-512': Crypto.Hash.SHA512,
            'Cryptoe HMAC-SHA-512': cryptoe_ext.HMAC_SHA512,
        },
    }

    for a in hmac_test_map:
        fl = hmac_test_map[a]['funcs']
        kl = hmac_test_map[a]['keys']
        l = hmac_test_map[a]['len']
        for k in kl:
            for m in test_messages:
                rv = []
                for f in fl:
                    if hasattr(fl[f], '__package__'):
                        dw = HMACWrapper(fl[f].__name__, fl[f], arg=getattr(Crypto.Hash, a))
                    else:
                        dw = HMACWrapper(fl[f].__name__, fl[f], arg=None)
                    mac = dw.digest(m, k, l/8)
                    if mac is None:
                        break
                    rv.append(mac)
                rv = list(set(rv))
                if len(k) * 8 > l:
                    result = resmap(len(rv)) + ' [EXPECTED]'
                else:
                    result = resmap(len(rv))
                print('HMAC {0:s} {1:d} {2:s}'.format(a, len(k), result))

if __name__ == '__main__':
    cryptoe_vs_openssl_digest()
    cryptoe_vs_openssl_hmac()
