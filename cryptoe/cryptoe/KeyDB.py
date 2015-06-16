from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker, relationship, backref
from sqlalchemy import create_engine, Column, Integer, String, Binary, DateTime, ForeignKey, \
    func
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.exc import NoResultFound

from KeyWrap import KW
from cryptoe import Random
from cryptoe.KeyMgmt import newkey_pbkdf, newkey_hkdf, pack_hkdf_info, newkey_rnd, DEFAULT_PRF_HASH, SHAd256_HEX
from cryptoe.exceptions import KeyLengthError, SaltLengthError
from utils import yubikey_passphrase_cr

KEYDB_USER = 'KeyDB'
KEYDB_PURPOSE_MASTER = 'KDB Master'
KEYDB_PURPOSE_WRAPPING = 'KDB Wrapping'
KEYDB_PURPOSE_DERIVATION = 'KDF'
KEYDB_PURPOSE_ROOT_ENC = 'Cipher Root Key'
KEYDB_PURPOSE_ROOT_MAC = 'HMAC Root Key'

KEYDB_PBKDF2_ITERATIONS = 2 ** 20
KEYDB_PASSPHRASE_LENGTH = 20
KEYDB_YUBIKEY_CR_SLOT = 2

Base = declarative_base()


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
    hash_shad256 = Column(String, nullable=False, unique=True)
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
    hash_shad256 = Column(String, nullable=False, unique=True)
    related_hash = Column(String, nullable=False)
    salt = relationship("Salt", backref=backref('salts.id', order_by=id))

    @property
    def hkdf_info(self):
        return pack_hkdf_info(self.purpose, self.user)


def new_random_key(maker, kek, purpose, user, klen=32):
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
    k.key = KW.wrap(kek, k_actual)
    k_hash = SHAd256_HEX(k_actual)
    k.hash_shad256 = k_hash
    k.related_hash = SHAd256_HEX(kek)
    session.add(k)
    session.commit()
    session.close()
    return [k_actual, k_hash]


def new_derived_key(maker, kek, kdk, purpose, user, klen=32):
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
        k.key = KW.wrap(kek, k_actual)
    k.related_hash = SHAd256_HEX(kdk)
    k_hash = SHAd256_HEX(k_actual)
    k.hash_shad256 = k_hash
    session.add(k)
    session.commit()
    session.close()
    return [k_actual, k_hash]


def new_salt(db_session, slen):
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


def init_keys(maker):
    from getpass import getpass

    passphrase_ready = 0
    session = maker()
    passphrase = ''
    while not passphrase_ready:
        passphrase = getpass('Master Passphrase: ').rstrip()
        if len(passphrase) < KEYDB_PASSPHRASE_LENGTH:
            print('Passphrase is too short.')
            continue
        else:
            confirm = getpass('Confirm Master Passphrase: ').rstrip()
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
    print('Generating database master key from provided passphrase.')
    print('Using PBKDF2 with %d rounds of %s' % (roundcount, mk.prf_hash))

    mk_key = newkey_pbkdf(klen, passphrase, mk_salt.salt, roundcount)
    if len(mk_key) != klen:
        raise KeyLengthError('PBKDF key is not of requested length (%d != %d)' % (len(mk_key), klen))
    mk_hash = SHAd256_HEX(mk_key)
    mk.hash_shad256 = mk_hash
    session.add(mk)
    session.commit()
    session.close()
    mk = None
    mk_salt = '\x00' * klen
    del mk
    del mk_salt

    print('Using master key to derive database key wrapping key')

    dk, dk_hash = new_derived_key(maker, kek='', kdk=mk_key, purpose=KEYDB_PURPOSE_WRAPPING, user=KEYDB_USER, klen=32)
    if len(dk) != klen:
        raise KeyLengthError('PBKDF key is not of requested length')
    mk_key = '\x00' * klen
    del mk_key

    print('Generating random database root key')

    dbk, dbk_hash = new_random_key(maker, kek=dk, purpose=KEYDB_PURPOSE_MASTER, user=KEYDB_USER, klen=32)
    if len(dbk) != klen:
        raise KeyLengthError('Random key is not of requested length')

    dk = '\x00' * klen
    del dk
    dbk = '\x00' * klen
    del dbk


def db_ready(maker):
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
    wk = session.query(Key).filter_by(hash_shad256=dbk.related_hash).one()
    mk = session.query(MasterKey).filter_by(hash_shad256=wk.related_hash).one()
    assert (len(dbk.salt.salt) == 0)
    assert (len(wk.salt.salt) == 32)
    assert (len(mk.salt.salt) == 32)
    assert (len(dbk.hash_shad256) == 64)
    assert (len(wk.hash_shad256) == 64)
    assert (len(mk.hash_shad256) == 64)
    assert (wk.user == KEYDB_USER and wk.purpose == KEYDB_PURPOSE_WRAPPING)
    session.close()
    return True


def initialize_db(dbu):
    """
    :type dbu: str
    """
    print('Preparing to create database.')
    engine = create_engine(dbu)
    objs = []
    Base.metadata.create_all(engine)
    sm = sessionmaker(bind=engine)
    if db_ready(sm) is True:
        print('Database already initialized!')
        return None
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
    engine = create_engine(dbu)
    sm = sessionmaker(bind=engine)
    return sm


def get_db_key(maker):
    from getpass import getpass

    session = maker()

    dbk = session.query(Key).filter_by(user=KEYDB_USER, purpose=KEYDB_PURPOSE_MASTER).order_by(Key.created.desc()).one()
    wk = session.query(Key).filter_by(hash_shad256=dbk.related_hash).one()
    mk = session.query(MasterKey).filter_by(hash_shad256=wk.related_hash).one()

    pw = getpass('passphrase: ').rstrip()
    pw = yubikey_passphrase_cr(pw)
    mk_key = newkey_pbkdf(32, pw, mk.salt.salt, mk.rounds)
    mk_key_hash = SHAd256_HEX(mk_key)
    if mk_key_hash != mk.hash_shad256:
        return None
    wk_key = newkey_hkdf(32,
                         mk_key,
                         wk.salt.salt,
                         pack_hkdf_info(wk.purpose, wk.user))
    wk_key_hash = SHAd256_HEX(wk_key)
    if wk_key_hash != wk.hash_shad256:
        return None

    dbk_key = KW.unwrap(wk_key, dbk.key)
    dbk_key_hash = SHAd256_HEX(dbk_key)
    if dbk_key_hash != dbk.hash_shad256:
        return None
    else:
        print('database key hash verified')
    session.close()
    return [dbk_key, dbk_key_hash]
