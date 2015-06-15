import base64

from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker, relationship, backref
from sqlalchemy import create_engine, Column, Integer, String, Binary, DateTime, ForeignKey, \
    func
from sqlalchemy.ext.declarative import declarative_base

from KeyWrap import KW
from cryptoe import Random
from cryptoe.KeyMgmt import newkey_pbkdf, newkey_hkdf, pack_hkdf_info, newkey_rnd, DEFAULT_PRF_HASH, SHAd256_HEX

KEYDB_USER = 'KeyDB'
KEYDB_PURPOSE_MASTER = 'KDB Master'
KEYDB_PURPOSE_WRAPPING = 'KDB Wrapping'
KEYDB_PURPOSE_DERIVATION = 'KDF'
KEYDB_PURPOSE_ROOT_ENC = 'Cipher Root Key'
KEYDB_PURPOSE_ROOT_MAC = 'HMAC Root Key'
KEYDB_PBKDF2_ITERATIONS = 2 ** 20

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
    k = Key()
    k.bits = klen * 8
    k.purpose = purpose
    k.user = user
    k.salt_id = no_salt.id
    k_actual = newkey_rnd(klen)
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
    k.salt_id = k_salt.id
    k.user = user
    k_actual = newkey_hkdf(klen, kdk, k_salt.salt, pack_hkdf_info(k.purpose, k.user))
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
    passphrase = ''
    session = maker()
    while not passphrase_ready:
        passphrase = getpass('Master Passphrase: ').rstrip()
        #        if len(passphrase) < 20:
        if len(passphrase) < 5:
            print('Passphrase is too short.')
            continue
        else:
            confirm = getpass('Confirm Master Passphrase: ').rstrip()
            if confirm == passphrase:
                passphrase_ready = 1
    del passphrase_ready

    roundcount = KEYDB_PBKDF2_ITERATIONS

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
    mk_key = '\x00' * klen
    del mk_key

    print('Generating random database root key')

    new_random_key(maker, kek=dk, purpose=KEYDB_PURPOSE_MASTER, user=KEYDB_USER, klen=32)
    dk = '\x00' * klen
    del dk


def db_ready(maker):
    session = maker()
    try:
        dbk = session.query(Key).filter_by(user=KEYDB_USER,
                                           purpose=KEYDB_PURPOSE_MASTER).one()  # .order_by(desc(Key.created))
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

    dbk = session.query(Key).filter_by(user=KEYDB_USER, purpose=KEYDB_PURPOSE_MASTER).one()
    wk = session.query(Key).filter_by(hash_shad256=dbk.related_hash).one()
    mk = session.query(MasterKey).filter_by(hash_shad256=wk.related_hash).one()

    pw = getpass('passphrase: ').rstrip()
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
    return [dbk_key, dbk_key_hash]

if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print('Usage: %s <database url (sqlalchemy format)>' % sys.argv[0])
        sys.exit(0)
    db_url = sys.argv[1]
    smaker = open_db(db_url)
    if not db_ready(smaker):
        smaker = initialize_db(db_url)
        init_keys(smaker)
    else:
        smaker = open_db(db_url)
        dbk_inf = get_db_key(smaker)
        print('dbk = %s' % base64.b64encode(dbk_inf[0]))
