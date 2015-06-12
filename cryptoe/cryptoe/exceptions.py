class CryptoError(Exception):
    """Top-level crypto exception"""


class CryptoKeyError(CryptoError):
    """Main class for Key-related errors"""


class NoKey(CryptoKeyError):
    """Key not set"""


class ImmutableError(CryptoKeyError):
    """Key already set"""


class DerivationError(CryptoKeyError):
    """A derived key did not pass checks"""
