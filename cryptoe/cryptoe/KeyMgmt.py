__author__ = 'Sean Davis <dive@endersgame.net>'
import os
import time
import math
import struct

from Crypto.Hash import HMAC, SHA512, SHA384

from Crypto.Protocol.KDF import PBKDF2

from cryptoe import Random
from cryptoe.exceptions import DerivationError, LowIterationCount, KeyLengthError

DEFAULT_PRF_HASH = SHA512
DEFAULT_PBKDF2_ITERATIONS = 2 ** 16
MINIMUM_PBKDF2_ITERATIONS = 2 ** 15


def hkdf_extract(salt, input_key_material, hash_obj=SHA512):
    """
    Extract a pseudorandom key suitable for use with hkdf_expand
    from the input_key_material and a salt using HMAC with the
    provided hash (default SHA-512).

    salt should be a random, application-specific byte string. If
    salt is None or the empty string, an all-zeros string of the same
    length as the hash's block size will be used instead per the RFC.

    See the HKDF draft RFC and paper for usage notes.
    """
    assert hasattr(hash_obj, 'digest_size')
    hash_len = hash_obj.digest_size
    assert isinstance(salt, str)
    if salt is None or len(salt) == 0:
        salt = chr(0) * hash_len
    return HMAC.new(salt, input_key_material, digestmod=hash_obj).digest()


def hkdf_expand(pseudo_random_key, info="", length=32, hash_obj=SHA512):
    """
    Expand `pseudo_random_key` and `info` into a key of length `bytes` using
    HKDF's expand function based on HMAC with the provided hash (default
    SHA-512). See the HKDF draft RFC and paper for usage notes.
    """
    assert hasattr(hash_obj, 'digest_size')
    hash_len = hash_obj.digest_size
    length = length
    if length > 255 * hash_len:
        raise Exception('Requested length exceeds 255*%d' % hash_len)
    blocks_needed = int(math.ceil(float(length) / float(hash_len)))
    okm = ''
    output_block = ''
    for counter in range(blocks_needed):
        output_block = HMAC.new(pseudo_random_key, output_block + info + chr(counter + 1), digestmod=hash_obj).digest()
        okm += output_block
    return okm[:length]


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
# 1) if label or context > 30 bytes, replace with the first 30 bytes of the SHAd256
#    digest of label (or context)
# 2) otherinfo = HMAC-SHAd256(label | label | context)[0..30]
#
# The final info bit string is packed in big-endian byte order.
#
# This was originally written to produce a much longer otherinfo value (512 bits),
# however as Dodis, Ristenpart, Steinberger & Tessaro reported in 2013, keying HMAC
# (or, by extension, HKDF) with a value equal to or larger than the output digest
# size could in fact weaken the overall construction.
#
# Hence, label and context are:
# 1) used as-is if less than 30 bytes
# 2) replaced with SHA-384 output truncated to 30 bytes if more than 30 bytes
# 3) used as input to HMAC-SHA512 keyed with label itself
#
# The intended result is that regardless of the size of label and context, the
# potential weakness on the second iterate of HMAC is avoided, as are weaknesses
# due to length extension (by virtue of using truncated hash output in all three
# steps)

# Further reading: http://eprint.iacr.org/2013/382.pdf

def pack_hkdf_info(label, context):
    if len(label) > 30:
        label = SHA384.new(label).digest()[:30]
    if len(context) > 30:
        context = SHA384.new(context).digest()[:30]
    h = HMAC.new(label, digestmod=SHA512)
    h.update(bytes(struct.pack('>30s', label)))
    h.update('\x00')
    h.update(bytes(struct.pack('>30s', context)))
    return h.digest()[:30]


def gather_easy_entropy(size):
    hm = HMAC.new('\x00' * (size / 8), digestmod=SHA512)  # Avoid extension attacks
    # 64 bits from time
    tm = time.time()
    hm.update(struct.pack('!L', int(2 ** 30 * (tm - math.floor(tm)))))
    hm.update(struct.pack('!L', int(math.ceil(tm))))
    del tm
    # 32 from clock
    ck = time.clock()
    hm.update(struct.pack('!L', int(2 ** 30 * (ck - math.floor(ck)))))
    del ck
    # 32 from PID * PPID
    pp = (os.getpid() * os.getppid()) % (2 ** 32 - 1)
    hm.update(struct.pack('!L', pp))
    del pp
    return hm.digest()[:size]


def newkey_rnd(klen=32):
    """
    Generate a key suitable for cryptographic use per NIST SP800-133

    :return: key
    """
    assert (klen > 0)
    assert (klen % 8 == 0)
    rbg = Random.new()
    u = rbg.read(klen)
    v = gather_easy_entropy(klen)
    k = ''.join(map(chr, map(lambda x: ord(x[0]) ^ ord(x[1]), zip(u, v))))
    return k


def newkey_pbkdf(klen=32, k_in='', salt='', rounds=DEFAULT_PBKDF2_ITERATIONS, prf=None):
    """
    Create a master key from user input, using PBKDF2.
    Return a list in the form of [Key object,salt]

    :param klen: desired key length in bytes
    :param k_in: password or passphrase
    :param rounds: number of iterations of the PRF
    :type klen: int
    :type k_in: str
    :type rounds: int
    """
    assert (klen > 0)
    assert (klen % 8 == 0)
    from cryptoe.Hash import SHAd256
    from Crypto.Hash import SHA384
    from Crypto.Hash import SHA512

    hash_choice = {
        32: SHAd256,
        48: SHA384,
        64: SHA512,
    }

    if klen not in [32, 48, 64]:
        raise KeyLengthError('Key length %d is not supported by this module.' % klen)
    if rounds < MINIMUM_PBKDF2_ITERATIONS:
        raise LowIterationCount('PBKDF2 should use >= %d iterations' % MINIMUM_PBKDF2_ITERATIONS)
    if not prf:
        hashobj = hash_choice[klen]
        ho_name = hashobj.__name__.split('.')[-1]
        print('[PBKDF] Deriving %d-bit key using HMAC-%s' % (klen * 8, ho_name))
        prf = lambda x, y: HMAC.new(x, y, hash_choice[klen]).digest()

    k = PBKDF2(k_in, salt, dkLen=klen, count=rounds, prf=prf)
    return k


def newkey_hkdf(klen=32, k_in='', salt='', otherinfo=''):
    """
    Derive a subkey of the current key using HKDF. Add it to the subkeys list.
    If no salt is specified, use a random salt of the same length as the current key.

    Returns a list in the form of [Key object,salt]

    :param klen: length of derived key in bytes
    :param k_in: input key from which to derive new key
    :param salt: Random hkdf_salt for HKDF expansion
    :param otherinfo: HKDF OtherInfo from pack_hkdf_info
    :type klen: int
    :type k_in: str
    :type salt: str
    :type otherinfo: str
    """
    assert (klen > 0)
    assert (klen % 8 == 0)
    if len(otherinfo) != 30:
        raise DerivationError('otherinfo supplied is not of expected length')
    if salt == '':
        rbg = Random.new()
        salt = rbg.read(klen / 8)
    elif len(salt) != klen:
        raise RuntimeError('salt length mismatch')
    from cryptoe.Hash import SHAd256
    from Crypto.Hash import SHA384
    from cryptoe.Hash import whirlpool

    hash_choice = {
        32: SHAd256,
        48: SHA384,
        64: whirlpool,
    }

    ho_name = hash_choice[klen].__name__.split('.')[-1]
    print('[HKDF] Deriving %d-bit key using HMAC-%s' % (klen * 8, ho_name))
    prk = hkdf_extract(salt, k_in, hash_obj=hash_choice[klen])
    k = hkdf_expand(prk, otherinfo, klen, hash_obj=hash_choice[klen])
    return k
