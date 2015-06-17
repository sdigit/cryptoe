from cryptoe.KeyMgmt import pack_hkdf_info, DEFAULT_PRF_HASH
from sqlalchemy import Column, Integer, String, Binary, DateTime, ForeignKey, \
    func
from sqlalchemy.orm import relationship, backref
from sqlalchemy.ext.declarative import declarative_base

from cryptoe.Hash import SHAd256
from cryptoe.exceptions import SaltLengthError, KeyLengthError

KEYDB_USER = 'KeyDB'
KEYDB_PURPOSE_MASTER = 'Root'
KEYDB_PURPOSE_WRAPPING = 'Wrapping'
KEYDB_PURPOSE_DERIVATION = 'KDF'
KEYDB_PURPOSE_ENCRYPTION = 'Encryption'
KEYDB_PURPOSE_AUTHENTICATION = 'HMAC'

KEYDB_PBKDF2_ITERATIONS = 2 ** 17
KEYDB_PASSPHRASE_LENGTH = 5

Base = declarative_base()


class HashAlgo(Base):
    __tablename__ = 'hash_algorithms'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)
    block_size = Column(Integer, nullable=False)
    digest_size = Column(Integer, nullable=False)


class Salt(Base):
    __tablename__ = 'salts'
    id = Column(Integer, primary_key=True)
    salt = Column(Binary, nullable=False, unique=True)


class MasterKey(Base):
    __tablename__ = 'master_keys'
    id = Column(Integer, primary_key=True)
    created = Column(DateTime, server_default=func.now(), nullable=False)
    prf_hash = Column(String, nullable=False)
    rounds = Column(Integer, nullable=False)
    salt_id = Column(Integer, ForeignKey('salts.id'))
    bits = Column(Integer, nullable=False)
    key_hash = Column(String, nullable=False, unique=True)
    salt = relationship("Salt", backref=backref('salts', order_by=id))


class Key(Base):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    created = Column(DateTime, server_default=func.now(), nullable=False)
    key = Column(Binary, server_default='')
    bits = Column(Integer, nullable=False)
    salt_id = Column(Integer, ForeignKey('salts.id'))
    purpose = Column(String, nullable=False)
    user = Column(String, nullable=False)
    key_hash = Column(String, nullable=False, unique=True)
    related_hash = Column(String, nullable=False)
    salt = relationship("Salt", backref=backref('salts.id', order_by=id))

    @property
    def hkdf_info(self):
        return pack_hkdf_info(self.purpose, self.user)


def new_random_key(maker, kek, purpose, user, klen=32):
    from cryptoe.KeyMgmt import newkey_rnd
    from cryptoe.KeyWrap import KWP

    session = maker()
    no_salt = session.query(Salt).filter_by(salt='').first()
    if len(no_salt.salt) != 0:
        raise SaltLengthError('Salt length for new_random_key should be 0')
    k = Key()
    k.bits = klen * 8
    k.purpose = purpose
    k.user = user
    k.salt_id = no_salt.id
    k_actual = newkey_rnd(klen)
    if len(k_actual) != klen:
        raise KeyLengthError('Key returned by newkey_rnd does not match requested length (%d != %d)' % (len(k_actual),
                                                                                                        klen))
    k.key = KWP.wrap(kek, k_actual)
    k_hash = SHAd256.new(k_actual).hexdigest()
    k.key_hash = k_hash
    k.related_hash = SHAd256.new(kek).hexdigest()
    session.add(k)
    session.commit()
    session.close()
    return k_actual


def new_salt(db_session, slen):
    from cryptoe import Random

    rbg = Random.new()
    s = Salt()
    s.salt = rbg.read(slen)
    salt = s.salt
    db_session.add(s)
    db_session.commit()
    s = db_session.query(Salt).filter_by(salt=salt).first()
    assert (s.salt == salt)
    del salt
    return s


def new_derived_key(maker, kek, kdk, purpose, user, klen=32):
    from cryptoe.KeyWrap import KWP
    from cryptoe.KeyMgmt import newkey_hkdf

    session = maker()
    k = Key()
    k.bits = klen * 8
    k.purpose = purpose
    k_salt = new_salt(session, klen)
    if len(k_salt.salt) != klen:
        raise SaltLengthError('HKDF salt must be the same length as the derivation key')
    k.salt_id = k_salt.id
    k.user = user
    k_actual = newkey_hkdf(klen, kdk, k_salt.salt, pack_hkdf_info(k.purpose, k.user))
    if len(k_actual) != klen:
        raise KeyLengthError('HKDF returned a key with an incorrect length (%d != %d)' % (len(k_actual),
                                                                                          klen))
    if kek == '':
        k.key = ''
    else:
        k.key = KWP.wrap(kek, k_actual)
    k.related_hash = SHAd256.new(kdk).hexdigest()
    k_hash = SHAd256.new(k_actual).hexdigest()
    k.key_hash = k_hash
    session.add(k)
    session.commit()
    session.close()
    return k_actual


def init_keys(maker):
    from getpass import getpass
    from cryptoe.exceptions import KeyLengthError
    from cryptoe.KeyMgmt import newkey_pbkdf
    from cryptoe.utils import yubikey_passphrase_cr

    passphrase_ready = 0
    session = maker()
    passphrase = ''
    while not passphrase_ready:
        passphrase = getpass('passphrase: ').rstrip()
        if len(passphrase) < KEYDB_PASSPHRASE_LENGTH:
            print('Passphrase is too short.')
            continue
        else:
            confirm = getpass('passphrase (confirm): ').rstrip()
            if confirm == passphrase:
                passphrase_ready = 1
    del passphrase_ready
    roundcount = KEYDB_PBKDF2_ITERATIONS
    passphrase = yubikey_passphrase_cr(passphrase)
    klen_bits = 256
    klen = klen_bits / 8

    mk_salt = new_salt(session, klen)
    mk = MasterKey()
    mk.bits = klen_bits
    mk.prf_hash = DEFAULT_PRF_HASH.__name__.split('.')[-1]
    mk.rounds = roundcount
    mk.salt_id = mk_salt.id

    mk_key = newkey_pbkdf(klen, passphrase, mk_salt.salt, roundcount)
    print('[INIT->PBKDF] %d-bit master key derived from user input' % len(mk_key) * 8)
    if len(mk_key) != klen:
        raise KeyLengthError('PBKDF key is not of requested length (%d != %d)' % (len(mk_key), klen))
    mk_hash = SHAd256.new(mk_key).hexdigest()
    mk.key_hash = mk_hash
    session.add(mk)
    session.commit()
    session.close()
    mk = None
    mk_salt = '\x00' * klen
    del mk
    del mk_salt

    kp = KEYDB_PURPOSE_WRAPPING
    wk = new_derived_key(maker, '', mk_key, kp, KEYDB_USER, klen)
    print('[INIT->KDF] %d-bit key (purpose: %s) derived' % (len(wk) * 8, kp))

    if len(wk) != klen:
        raise KeyLengthError('[INIT->KDF] %d != %d' % (len(wk), klen))
    mk_key = '\x00' * klen
    del mk_key

    dbk_list = [
        [
            'encryption',
            32,
            KEYDB_PURPOSE_ENCRYPTION,
        ],
        [
            'authentication',
            32,
            KEYDB_PURPOSE_AUTHENTICATION,
        ],
        [
            'authentication',
            48,
            KEYDB_PURPOSE_AUTHENTICATION,
        ],
        [
            'authentication',
            64,
            KEYDB_PURPOSE_AUTHENTICATION,
        ],
    ]

    for k in dbk_list:
        rk = new_random_key(maker, wk, k[2], KEYDB_USER, k[1])
        if len(rk) != k[1]:
            raise KeyLengthError('[INIT->RND] %d != %d' % (len(rk), k[1]))
        else:
            print('[INIT->RND] %d-bit key "%s" created and wrapped' % (len(rk) * 8, k[2]))

        rk = '\x00' * klen
        del rk
    wk = '\x00' * 32
    del wk


def db_ready(maker):
    from sqlalchemy.orm.exc import NoResultFound
    from sqlalchemy.exc import OperationalError

    session = maker()
    try:
        dbk = session.query(Key).filter_by(user=KEYDB_USER,
                                           purpose=KEYDB_PURPOSE_MASTER).one()  # .order_by(desc(Key.created))
    except NoResultFound:
        session.close()
        return False
    except OperationalError:
        session.close()
        return False
    wk = session.query(Key).filter_by(key_hash=dbk.related_hash).one()
    mk = session.query(MasterKey).filter_by(key_hash=wk.related_hash).one()
    assert (len(dbk.salt.salt) == 0)
    assert (len(wk.salt.salt) == 32)
    assert (len(mk.salt.salt) == 32)
    assert (len(dbk.key_hash) in [48, 64])
    assert (len(wk.key_hash) in [48, 64])
    assert (len(mk.key_hash) in [48, 64])
    assert (wk.user == KEYDB_USER and wk.purpose == KEYDB_PURPOSE_WRAPPING)
    session.close()
    return True


def initialize_db(dbu):
    """
    :type dbu: str
    """
    sm = open_db(dbu)
    Base.metadata.create_all(sm.kw['bind'])
    if db_ready(sm) is True:
        print('Database already initialized!')
        return None
    objs = []
    hash_info = {
        'Whirlpool': {
            'digest_size': 512,
            'block_size': 512,
        },
        'SHA256': {
            'digest_size': 256,
            'block_size': 512,
        },
        'SHA384': {
            'digest_size': 384,
            'block_size': 1024,
        },
        'SHA512': {
            'digest_size': 512,
            'block_size': 1024,
        },
    }
    for hi in hash_info:
        h = HashAlgo()
        h.name = hi
        h.digest_size = hash_info[hi]['digest_size'] / 8
        h.block_size = hash_info[hi]['block_size'] / 8

    session = sm()
    for o in objs:
        session.add(o)
    no_salt = Salt()
    no_salt.salt = ''
    session.add(no_salt)
    session.commit()
    session.close()
    return sm


def open_db(dbu):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    engine = create_engine(dbu)
    sm = sessionmaker(bind=engine)
    return sm


def get_db_keys(maker):
    from getpass import getpass
    from cryptoe.KeyMgmt import newkey_pbkdf, newkey_hkdf
    from cryptoe.KeyWrap import KWP
    from utils import yubikey_passphrase_cr

    session = maker()

    dbk = session.query(Key).filter_by(user=KEYDB_USER, purpose=KEYDB_PURPOSE_MASTER).order_by(Key.created.desc()).one()
    wk = session.query(Key).filter_by(key_hash=dbk.related_hash).one()
    mk = session.query(MasterKey).filter_by(key_hash=wk.related_hash).one()

    pw = getpass('passphrase: ').rstrip()
    pw = yubikey_passphrase_cr(pw)
    mk_key = newkey_pbkdf(32, pw, mk.salt.salt, mk.rounds)
    mk_key_hash = SHAd256.new(mk_key).hexdigest()
    if mk_key_hash != mk.key_hash:
        return None
    wk_key = newkey_hkdf(32,
                         mk_key,
                         wk.salt.salt,
                         pack_hkdf_info(wk.purpose, wk.user))
    wk_key_hash = SHAd256.new(wk_key).hexdigest()
    if wk_key_hash != wk.key_hash:
        return None

    dbk_key = KWP.unwrap(wk_key, dbk.key)
    dbk_key_hash = SHAd256.new(dbk_key).hexdigest()
    if dbk_key_hash != dbk.key_hash:
        return None
    else:
        print('database key hash verified')
    session.close()
    return [dbk_key, dbk_key_hash]
