import unittest
import struct
from Crypto.Hash import SHA256
from Crypto.Random import random
import sys

NISTV1 = [3, 0x616263]
NISTV2 = [
    56,
    0x6162636462636465636465666465666765666768666768696768696a68696a6b696a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071

]
NISTV3 = [1000000, 'a' * 1000000]

NIST_FIPS_VECTORS = [NISTV1, NISTV2, NISTV3]


def long2ba(val):
    """
    Convert a long integer into a bytearray

    :param val: a long integer
    :return: bytearray
    """
    b = bytearray()
    n = abs(val)
    while n > 0:
        b += struct.pack('<B', n % 256)
        n >>= 8
    return bytearray(reversed(b))


def py_SHAd256(msg):
    """
    SHAd256 implementation for digesting something all at once (because Crypto.Random.Fortuna.SHAd256 uses the older
    recommendation from Practical Cryptography; this is the recommendation from Cryptography Engineering)
    :param msg: message to hash
    """
    sha = SHA256.new()
    sha.update('\x00' * 64)
    sha.update(msg)
    return SHA256.new(sha.digest()).digest()


class test_SHAd256(unittest.TestCase):
    """
    Compare output of Python implementation of SHAd-256 to output of C implementation
    cryptoe.KeyMgmt.SHAd256(m) vs. cryptoe.Hash.SHAd256.new(m).digest()
    Vectors from FIPS 180-2 Appendix B
    """

    def test_python_vs_c_NIST(self):
        from cryptoe.Hash import SHAd256 as ct_SHAd256

        for v in NIST_FIPS_VECTORS:
            data = v[1]
            if isinstance(data, int):
                data = long2ba(data)
            if isinstance(data, long):
                data = long2ba(data)
            data = bytes(data)
            ct_hash = ct_SHAd256.new(data).digest()
            py_hash = py_SHAd256(data)
            self.assertEqual(ct_hash, py_hash)

    def test_python_vs_c_RND(self):
        from Crypto import Random
        from cryptoe.Hash import SHAd256 as ct_SHAd256

        rnd_buf_lens = sorted(list(set([random.randint(0, 4096) for _ in xrange(0, 64)])))
        for r in xrange(0, len(rnd_buf_lens)):
            sys.stdout.flush()
            data = Random.new().read(rnd_buf_lens[r])
            ct_hash = ct_SHAd256.new(data).digest()
            py_hash = py_SHAd256(data)
            self.assertEqual(ct_hash, py_hash)


if __name__ == '__main__':
    unittest.main()
