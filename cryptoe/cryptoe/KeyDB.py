from cryptoe import Random
from cryptoe.KeyMgmt import generate_key
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


class Key(Base):
    __tablename__ = 'keys'
    id = Column(Integer, primary_key=True)
    mk_id = Column(Integer, ForeignKey('master_keys.id'))
    wrapped = Column(Binary, server_default='NULL')
    hash = Column(String, nullable=False)
    bits = Column(Integer, nullable=False)
    lvl = Column(Integer, nullable=False)
    src = Column(Integer, nullable=False)
    use = Column(Integer, nullable=False)
    created = Column(DateTime, server_default='now()', nullable=False), CheckConstraint('created = now()')


def initialize_db(db_url):
    """
    :type db_url: str
    """
    print('Preparing to create database.')
    root_key = generate_key()

    engine = create_engine(db_url)
    Base.metadata.create_all(engine)

if __name__ == '__main__':
    import sys

    if len(sys.argv) != 2:
        print('Usage: %s <database url (sqlalchemy format)>' % sys.argv[0])
        sys.exit(0)
    initialize_db(sys.argv[1])
