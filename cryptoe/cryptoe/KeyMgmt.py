from collections import OrderedDict
import struct

from Crypto.Hash import HMAC, SHA512
from Crypto.Protocol.KDF import PBKDF2
from sqlalchemy import create_engine, Column, Integer, String, Binary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import hkdf

from cryptoe import Random, DEFAULT_PBKDF2_ITERATIONS

KEY_SRC_RAND = 0
KEY_SRC_PBKDF = 1
KEY_SRC_HKDF = 2

KEY_USE_ROOT = 0
KEY_USE_DERIVATION = 1
KEY_USE_HMAC = 2
KEY_USE_ENCRYPTION = 4
KEY_USE_WRAPPING = 8
KEY_USE_IV_SEED = 16

KEY_ALG_NONE = 0
KEY_ALG_CIPHER = 1
KEY_ALG_MAC = 2
KEY_ALG_BLK_AES = 4
KEY_ALG_BLK_TWOFISH = 8
KEY_ALG_BLK_SERPENT = 16
KEY_ALG_HMAC_SHA256 = 32
KEY_ALG_HMAC_SHA384 = 64
KEY_ALG_HMAC_SHA512 = 128

PRF_NONE = 0
PRF_HMAC_SHA512 = 1

KEY_INFO_SRC = OrderedDict({
    KEY_SRC_RAND: 'Fortuna',
    KEY_SRC_PBKDF: 'PBKDF2',
    KEY_SRC_HKDF: 'HKDF',
})

KEY_INFO_USE = OrderedDict({
    KEY_USE_ROOT: 'Master Key',
    KEY_USE_DERIVATION: 'Key Derivation Key',
    KEY_USE_HMAC: 'Message Digest Key',
    KEY_USE_ENCRYPTION: 'Symmetric Cipher Key',
    KEY_USE_WRAPPING: 'Key Encryption Key',
    KEY_USE_IV_SEED: 'IV Generation Key',
})

KEY_INFO_PRF = OrderedDict({
    PRF_NONE: 'No PRF used',
    PRF_HMAC_SHA512: 'PRF was HMAC-SHA512',
})

KEY_INFO_ALG = OrderedDict({
    KEY_ALG_NONE: 'Algorithm unspecified or not applicable',
    KEY_ALG_CIPHER: 'Symmetric Cipher',
    KEY_ALG_MAC: 'Keyed Message Authentication',
    KEY_ALG_BLK_AES: 'Advanced Encryption Standard',
    KEY_ALG_BLK_TWOFISH: 'Twofish',
    KEY_ALG_BLK_SERPENT: 'Serpent',
    KEY_ALG_HMAC_SHA256: 'SHA-256',
    KEY_ALG_HMAC_SHA384: 'SHA-384',
    KEY_ALG_HMAC_SHA512: 'SHA-512',
})

KEY_INFO_SIZE = 64


class KeyInfo(object):
    """
    Binary string representation of label and context for HKDF
    +---+---+---+----+---+---+---+---+----+
    |use|usr|num|RSVD|pad|lvl|src|prf|RSVD|
    | 2 | 16| 2 |  8 | 1 | 1 | 1 | 1 |  8 |
    +---+---+---+----+---+---+---+---+----+
    """
    fmt = '!H16sHQxBBBQ'
    ki_struct = struct.Struct(fmt)

    @staticmethod
    def encode(use, usr, num, lvl, src, prf):
        """
        Pack given values into a KeyInfo bytearray
        """
        buf = bytearray(40)
        KeyInfo.ki_struct.pack_into(buf, 0, use, usr, num, 0, lvl, src, prf, 0)
        return buf

    @staticmethod
    def decode(buf):
        """
        Unpack the specified buffer, extracting the label and context values

        Binary string representation of label and context for HKDF

        |use|usr|num|pad|lvl|src|prf|
        | 2 | 16| 2 | 1 | 1 | 1 | 1 |
        """
        return KeyInfo.ki_struct.unpack_from(buf)


class CryptoKeyError(Exception):
    """Main class for Key-related errors"""


class NoKey(CryptoKeyError):
    """Key not set"""


class ImmutableError(CryptoKeyError):
    """Key already set"""


class DerivationError(CryptoKeyError):
    """A derived key did not pass checks"""


Base = declarative_base()
engine = None
Session = None
session = None


class Key(Base):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    bits = Column(Integer)
    lvl = Column(Integer)
    src = Column(Integer)
    salt = Column(Binary)
    subkeys = Column(Integer)
    parent = Column(Integer)
    info = Column(String)

    def __init__(self):
        self._key = ''
        self.salt = ''
        self.subkeys = 0
        self.parent = 0

    @property
    def key(self):
        if self.key == '':
            raise NoKey('key is not set')
        else:
            return self.key

    @key.setter
    def key(self, data):
        assert (type(data) == str)
        if self.key != '':
            raise ImmutableError('Key data already set')
        assert (self.key == '')
        self.key = data

    @info.setter
    def info(self, data):
        assert (type(data) == str)
        if self._info != '':
            raise ImmutableError('Key info already set')
        self.info = data

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
        k.lvl = self.lvl + 1
        k.src = KEY_SRC_HKDF
        self.subkeys += 1
        k.parent = self.id
        return k


def create_mk(pw, salt='', rounds=DEFAULT_PBKDF2_ITERATIONS, dklen=32):
    """
    Create a master key from user input, using PBKDF2.
    Return a list in the form of [Key object,salt]

    :param pw: password or passphrase
    :param salt: salt for PBKDF2 (if not specified, will be generated randomly)
    :param rounds: number of iterations of the PRF
    :param dklen: desired key length in bytes
    :type pw: str
    :type salt: str
    :type rounds: int
    :type dklen: int
    """
    if dklen < 16 or dklen > 1024:
        raise DerivationError('Requested key must be between 16 and 1024 bytes')
    if salt == '':
        kdf_salt = Random.new().read(64)
    elif len(salt) < 16:
        raise RuntimeError('salt smaller than minimum')
    else:
        kdf_salt = salt

    prf = lambda k, s: HMAC.new(k, s, SHA512).digest()

    mk = Key()
    mk.bits = dklen * 8
    mk.info = 'PBKDF2,%d,%d,%s[%d,%d]' % (dklen * 8, rounds, SHA512.__name__, SHA512.block_size, SHA512.digest_size)
    mk.lvl = 0
    mk.src = KEY_SRC_PBKDF
    mk.key = PBKDF2(pw, kdf_salt, dkLen=dklen, count=rounds, prf=prf)
    mk.salt = kdf_salt
    return mk


def dbinit(dbpath):
    global engine
    global Session
    global session
    engine = create_engine('sqlite:///' + str(dbpath))
    Session = sessionmaker(engine)
    session = Session()
