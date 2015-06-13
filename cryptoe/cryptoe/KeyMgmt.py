from collections import OrderedDict
from math import floor, ceil
import os
import struct
import time

from Crypto.Hash import HMAC, SHA512, SHA256

from Crypto.Protocol.KDF import PBKDF2
import hkdf

from cryptoe import Random, DEFAULT_PBKDF2_ITERATIONS
from cryptoe.exceptions import DerivationError

KEY_SRC_NONE = 0
KEY_SRC_RAND = 1
KEY_SRC_PBKDF = 2
KEY_SRC_HKDF = 4

KEY_USE_NONE = 0
KEY_USE_ROOT = 1
KEY_USE_DERIVATION = 2
KEY_USE_HMAC = 4
KEY_USE_ENCRYPTION = 8
KEY_USE_WRAPPING = 16
KEY_USE_IV_SEED = 32

KEY_ALG_NONE = 0
KEY_ALG_OTHER = 1
KEY_ALG_CIPHER = 2
KEY_ALG_MAC = 4
KEY_ALG_BLK_AES = 8
KEY_ALG_BLK_TWOFISH = 16
KEY_ALG_BLK_SERPENT = 32
KEY_ALG_HMAC_SHA256 = 64
KEY_ALG_HMAC_SHA384 = 128
KEY_ALG_HMAC_SHA512 = 256

PRF_NONE = 0
PRF_HMAC_SHA256 = 1
PRF_HMAC_SHA384 = 2
PRF_HMAC_SHA512 = 4

KEY_INFO_SRC = OrderedDict({
    KEY_SRC_RAND: 'Fortuna',
    KEY_SRC_PBKDF: 'PBKDF2',
    KEY_SRC_HKDF: 'HKDF',
})

KEY_INFO_USE = OrderedDict({
    KEY_USE_ROOT: 'Master Key',
    KEY_USE_DERIVATION: 'Key Derivation Key',
    KEY_USE_HMAC: 'Keyed-Hash Message Authentication Code [HMAC]',
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

KEY_INFO_USRID_LEN = 104 / 8
KEY_INFO_APPID_LEN = 104 / 8

# pack_hkdf_info and unpack_hkdf_info encode and decode the otherinfo data used by the extraction step of HKDF.
#
# RFC5869 states in section 3.2:
#
# 3.2.  The 'info' Input to HKDF
#
#   While the 'info' value is optional in the definition of HKDF, it is
#   often of great importance in applications.  Its main objective is to
#   bind the derived key material to application- and context-specific
#   information.  For example, 'info' may contain a protocol number,
#   algorithm identifiers, user identities, etc.  In particular, it may
#   prevent the derivation of the same keying material for different
#   contexts (when the same input key material (IKM) is used in such
#   different contexts).  It may also accommodate additional inputs to
#   the key expansion part, if so desired (e.g., an application may want
#   to bind the key material to its length L, thus making L part of the
#   'info' field).  There is one technical requirement from 'info': it
#   should be independent of the input key material value IKM.
#
# SP800-56C states in section 6.1 and 6.2:
#
# 1. Label - A binary string that identifies the purpose for the derived keying material.
# For example, it can be the ASCII code for a character string. The value and encoding
# method used for the Label are defined in a larger context, for example, in the protocol
# that uses this key derivation procedure.
# 2. Context - A binary string containing the information related to the derived keying
# material. When a static key pair can be used in more than one key establishment
# scheme, the Context should include a scheme identifier that is unique to the scheme
# employed during the particular key establishment transaction that invoked the key
# expansion process. If the information is available, Context should include the
# identifiers of the parties who are deriving and/or using the derived keying material
# and, optionally, a nonce known by the parties who derive the keys. Context is
# equivalent to the data field "OtherInfo" used by the single-step key derivation
# functions defined in NIST SP 800-56A and SP 800-56B. (See Section 5.8 of SP 800-
# 56A or Section 5.9 of SP 800-56B for suggested formats for "OtherInfo".)
#
# And also in section 6:
#
# For the inputs to the key expansion step, each data field shall be encoded unambiguously.
# When concatenating the above encoded data fields, the length for each data field and the
# order for the fields may be defined as a part of a key expansion specification or by the
# protocol where the key expansion step is used.
#
# When using one of the KDF modes defined in SP 800-108 for the key expansion step, the
# fixed portion of the message input during execution of HMAC-hash or AES-CMAC
# could, for example, be represented as P = Label || 0x00 || Context || [L]2 (i.e., a
# concatenation of a Label, which is assumed to be the ASCII code for a character string;
# an ending indicator of Label, 0x00; Context; and [L]2). Other formats are allowed, as long
# as they are well-defined by the key expansion implementation or by the protocol
# employing this key derivation procedure.
#
#
# With both RFC5869 and SP800-56C in mind, we construct our info field as follows:
# label (31 bytes) + 0x00 + context (31 bytes)
#
# The final info bit string is packed in big-endian byte order.
#
# The overall 64-byte length was chosen mostly for convenience
#
# [  size  ]    name    description
# ---------------------------------
# [248 bits]    LABEL
# ---------------------------------
# [  8 bits]    len     length of the final binary string LABEL in bytes
# [ 16 bits]    use     bitwise OR of KEY_USE_HMAC and any other relevant KEY_USE_* values
# [ 16 bits]    alg     bitwise OR of all relevant KEY_ALG_* values (KEY_ALG_OTHER if none apply)
# [128 bits]    desc    optional freeform text description
# [ 64 bits]    rsvd    unused, reserved for future use
# [ 16 bits]    tag     the integer 1984 shifted left by 4 bits (31744)
# ---------------------------------
# [  8 bits] zero byte (to separate label and context per SP800-56C)
# ---------------------------------
# [256 bits] CONTEXT
# ---------------------------------
# [  8 bits]    len     length of the final binary string CONTEXT in bytes
# [104 bits]    usrid   user identifier
# [104 bits]    appid   application identifier
# [ 24 bits]    rsvd    unused, reserved for future use
# [ 16 bits]    tag     the integer 1975 shifted left by 4 bits (31600)


def pack_hkdf_info(use, alg, user, desc):
    assert (isinstance(use, int))
    assert (isinstance(alg, int))
    assert (isinstance(user, str))
    assert (isinstance(desc, str))
    assert (len(user) <= 104 * 8)
    assert (use & KEY_USE_HMAC)
    label_struct = struct.Struct('>BHH16s8xH')
    context_struct = struct.Struct('>B13s13s3xH')
    buf = bytearray(64)
    LABEL_LEN = 31
    LABEL_TAG = 1984 << 4
    CONTEXT_TAG = 1975 << 4
    CONTEXT_LEN = 32
    label_struct.pack_into(buf, 0, LABEL_LEN, use, alg, desc, LABEL_TAG)
    struct.pack_into('>B', buf, 31, 0x00)
    context_struct.pack_into(buf, 32, CONTEXT_LEN, user, 'cryptoe', CONTEXT_TAG)
    return buf


def unpack_hkdf_info(buf):
    if (len(buf)) != 64:
        print('len(buf) != 64: %d' % len(buf))
    label_struct = struct.Struct('>BHH16s8xH')
    context_struct = struct.Struct('>B13s13s3xH')
    vals = {
        'label': label_struct.unpack_from(buf, 0),
        'context': context_struct.unpack_from(buf, 32),
    }
    return vals


def gather_easy_entropy(size=256):
    assert (size == 256 or size == 128)
    hm = HMAC.new('\x00' * (size / 8), digestmod=SHA256)  # Avoid extension attacks
    # 64 bits from time
    tm = time.time()
    hm.update(struct.pack('!L', int(2 ** 30 * (tm - floor(tm)))))
    hm.update(struct.pack('!L', int(ceil(tm))))
    del tm
    # 32 from clock
    ck = time.clock()
    hm.update(struct.pack('!L', int(2 ** 30 * (ck - floor(ck)))))
    del ck
    # 32 from PID * PPID
    pp = (os.getpid() * os.getppid()) % (2 ** 32 - 1)
    hm.update(struct.pack('!L', pp))
    del pp
    return hm.digest()[:size / 8]


def generate_key(size=256):
    """
    Generate a key suitable for cryptographic use per NIST SP800-133

    :return: key
    """
    assert (size == 256 or size == 128)
    rbg = Random.new()
    u = rbg.read(size / 8)
    v = gather_easy_entropy(size)
    k = ''.join(map(chr, map(lambda x: ord(x[0]) ^ ord(x[1]), zip(u, v))))
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
    :rtype: MasterKey
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

    key = PBKDF2(pw, kdf_salt, dkLen=dklen, count=rounds, prf=prf)
    return {'key': key, 'salt': salt}


def create_dk(key, dklen=32, kdf_info='', hkdf_salt=''):
    """
    Derive a subkey of the current key using HKDF. Add it to the subkeys list.
    If no salt is specified, use a random salt of the same length as the current key.

    Returns a list in the form of [Key object,salt]

    :param hkdf_salt: Random hkdf_salt for HKDF expansion
    :param dklen: length of derived key
    :type hkdf_salt: str
    :type dklen: int
    """
    if dklen < 16 or dklen > 1024:
        raise DerivationError('Requested key must be between 16 and 1024 bytes')
    if hkdf_salt == '':
        hkdf_salt = Random.new().read(dklen)
    prk = hkdf.hkdf_extract(hkdf_salt, key)
    dk = hkdf.hkdf_expand(prk, info=kdf_info, length=dklen)
    return dk


def key_hash(key):
    return SHA256.new(key).hexdigest()
