from Crypto.Hash import HMAC, SHA512
from Crypto.Protocol.KDF import PBKDF2
from cryptoe import Random, DEFAULT_PBKDF2_ITERATIONS
import hkdf


class CryptoKeyError(Exception):
    """Main class for Key-related errors"""


class NoKey(CryptoKeyError):
    """Key not set"""


class ImmutableError(CryptoKeyError):
    """Key already set"""


class DerivationError(CryptoKeyError):
    """A derived key did not pass checks"""


class Key(object):
    def __init__(self):
        self._key = ''
        self._info = ''
        self._bytelen = 0
        self._subkeys = []

    @property
    def bits(self):
        assert (self._bytelen != 0)
        return self._bytelen * 8

    @bits.setter
    def bits(self, nbits):
        assert (nbits % 8 == 0)
        self._bytelen = nbits / 8

    @property
    def bytes(self):
        return self._bytelen

    @bytes.setter
    def bytes(self, nbytes):
        self._bytelen = nbytes

    @property
    def key(self):
        if self._key == '':
            raise NoKey('key is not set')
        else:
            return self._key

    @key.setter
    def key(self, data):
        assert (type(data) == str)
        if self._key != '':
            raise ImmutableError('Key data already set')
        assert (self._key == '')
        self._key = data

    @property
    def info(self):
        return self._info

    @info.setter
    def info(self, data):
        assert (type(data) == str)
        if self._info != '':
            raise ImmutableError('Key info already set')
        self._info = data

    @property
    def ok(self):
        if self._bytelen == 0 or self._bytelen % 2 != 0:
            return False
        for a in ['_key', '_info']:
            if getattr(self, a) == '':
                return False
        return True

    def DeriveKey(self, info, hkdf_salt='', dklen=32):
        """
        Derive a subkey of the current key using HKDF. Add it to the subkeys list.
        If no salt is specified, use a random salt of the same length as the current key.

        Returns a list in the form of [Key object,salt]

        :param info: key info (used for key derivation)
        :param hkdf_salt: Random hkdf_salt for HKDF expansion
        :param dklen: length of derived key
        :type info: str
        :type hkdf_salt: str
        :type dklen: int
        """
        if dklen < 16 or dklen > 1024:
            raise DerivationError('Requested key must be between 16 and 1024 bytes')
        if hkdf_salt == '':
            hkdf_salt = Random.new().read(dklen)
        prk = hkdf.hkdf_extract(hkdf_salt, self._key)
        k = Key()
        k.bits = dklen * 8
        k.info = info
        k.key = hkdf.hkdf_expand(prk, info=info, length=dklen)
        if k.ok:
            self._subkeys.append(k)
            return k
        else:
            raise DerivationError('key.ok is false')


def create_mk(pw, kdf_salt='', rounds=DEFAULT_PBKDF2_ITERATIONS, dklen=32):
    """
    Create a master key from user input, using PBKDF2.
    Return a list in the form of [Key object,salt]

    :param pw: password or passphrase
    :param kdf_salt: salt for PBKDF2 (if not specified, will be generated randomly)
    :param rounds: number of iterations of the PRF
    :param dklen: desired key length in bytes
    :type pw: str
    :type kdf_salt: str
    :type rounds: int
    :type dklen: int
    """
    if dklen < 16 or dklen > 1024:
        raise DerivationError('Requested key must be between 16 and 1024 bytes')
    if len(kdf_salt) < 16:
        raise RuntimeError('salt smaller than minimum')
    elif kdf_salt == '':
        kdf_salt = Random.new().read(64)
    else:
        kdf_salt = kdf_salt
    prf = lambda k, s: HMAC.new(k, s, SHA512).digest()

    mk = Key()
    mk.bits = dklen * 8
    mk.info = 'PBKDF2,%d,%d,%s[%d,%d]' % (dklen * 8, rounds, SHA512.__name__, SHA512.block_size, SHA512.digest_size)
    mk.key = PBKDF2(pw, kdf_salt, dkLen=dklen, count=rounds, prf=prf)
    if mk.ok:
        return [mk, kdf_salt]
    else:
        raise DerivationError('key.ok is false')
