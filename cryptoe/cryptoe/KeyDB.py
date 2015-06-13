from sqlalchemy.orm import sessionmaker
from cryptoe import Random
from cryptoe.KeyMgmt import generate_key, create_mk, key_hash, create_dk, pack_hkdf_info, KEY_USE_HMAC, \
    KEY_ALG_HMAC_SHA512, KEY_USE_DERIVATION, KEY_ALG_CIPHER, KEY_ALG_MAC, KEY_ALG_BLK_AES, KEY_INFO_USRID_LEN, \
    unpack_hkdf_info
from sqlalchemy import create_engine, Column, Integer, String, Binary, DateTime, ForeignKey, \
    CheckConstraint
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Hash(Base):
    __tablename__ = 'hashes'
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    block_size = Column(Integer, nullable=False)
    digest_size = Column(Integer, nullable=False)


class KDFReference(Base):
    __tablename__ = 'kdf_reference'
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    refdoc = Column(String, nullable=False)


class KDF(Base):
    __tablename__ = 'kdf'
    id = Column(Integer, primary_key=True)
    hash_id = Column(Integer, ForeignKey('hashes.id'))
    name = Column(String, nullable=False)


class MasterKey(Base):
    __tablename__ = 'mk'
    id = Column(Integer, primary_key=True)
    wrapped = Column(Binary, server_default='NULL')
    hash = Column(String, unique=True, nullable=False)
    created = Column(DateTime, server_default='CURRENT_TIMESTAMP', nullable=False)
    name = Column(String, server_default='')
    method = Column(String, nullable=False)
    hash_algo = Column(String, nullable=False)
    salt = Column(Binary, server_default='NULL')
    rounds = Column(Integer, server_default='20000', nullable=False)


class Key(Base):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    mk_id = Column(Integer, ForeignKey('mk.id'))
    wrapped = Column(Binary, server_default='NULL')
    hash = Column(String, nullable=False)
    bits = Column(Integer, nullable=False)
    lvl = Column(Integer, nullable=False)
    src = Column(Integer, nullable=False)
    use = Column(Integer, nullable=False)
    created = Column(DateTime, server_default='now()', nullable=False), CheckConstraint('created = now()')


def init_keys():
    from getpass import getpass
    import os

    mk_pw_ok = 0
    mk_pw = ''
    dk_use = KEY_USE_HMAC | KEY_USE_DERIVATION
    dk_alg = KEY_ALG_CIPHER | KEY_ALG_MAC | KEY_ALG_BLK_AES | KEY_ALG_HMAC_SHA512
    rng = Random.new()

    print('* initializing database keys')

    print('step 1: create MK')
    while not mk_pw_ok:
        mk_pw = getpass('Enter passphrase: ').rstrip()
        mk_pw_cnf = getpass('Confirm passphrase: ').rstrip()
        if mk_pw == mk_pw_cnf:
            mk_pw_ok = 1
        mk_pw_cnf = ''
        del mk_pw_cnf

    mk_salt = rng.read(32)
    mk = create_mk(mk_pw, mk_salt)
    assert (mk_salt == mk['salt'])
    mk = mk['key']
    mk_hash = key_hash(mk)
    print(' key hash is %s' % mk_hash)

    print('step 2: derive DPK from MK')
    dk_user = os.getlogin()
    if len(dk_user) > KEY_INFO_USRID_LEN:
        dk_user_new = dk_user[:KEY_INFO_USRID_LEN]
        print('step 2: [hkdf info] Truncating %s to %s' % (dk_user, dk_user_new))
        dk_user = dk_user_new
        del dk_user_new
    dk_info = pack_hkdf_info(dk_use, dk_alg, dk_user, 'init_keys')
    print('step 2: [hkdf info] info: %s' % unpack_hkdf_info(dk_info))
    dk_salt = rng.read(64)
    dpk = create_dk(mk, 32, dk_info, dk_salt)
    dpk_hash = key_hash(dpk)
    print(' key hash is %s' % dpk_hash)

    print('step 3: create DB master key')
    db_mk = generate_key(256)
    db_mk_hash = key_hash(db_mk)
    print(' key hash is %s' % db_mk_hash)


def initialize_db(db_url):
    """
    :type db_url: str
    """
    print('Preparing to create database.')
    engine = create_engine(db_url)
    hashes = [
        ['SHA-256', 256, 512],
        ['SHA-384', 512, 1024],
        ['SHA-512', 512, 1024],
    ]
    kdf_references = [
        ['PBKDF','SP800-132'],
        ['HKDF','RFC5869'],
    ]
    objs = []
    for h in hashes:
        ho = Hash()
        ho.name = h[0]
        ho.digest_size = h[1]
        ho.block_size = h[2]
        objs.append(ho)
    for k in kdf_references:
        kdfref = KDFReference()
        kdfref.name = k[0]
        kdfref.refdoc = k[1]
        objs.append(kdfref)

    Base.metadata.create_all(engine)
    sm = sessionmaker(bind=engine)
    session = sm()
    for h in objs:
        session.add(h)
    session.commit()
    session.close()

if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print('Usage: %s <database url (sqlalchemy format)>' % sys.argv[0])
        sys.exit(0)
    initialize_db(sys.argv[1])
    init_keys()
