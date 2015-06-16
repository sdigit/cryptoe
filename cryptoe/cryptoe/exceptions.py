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


class KeyLengthError(CryptoKeyError):
    """Returned key is not of expected length"""


class SaltError(CryptoError):
    """Main class for Salt-related errors"""


class SaltLengthError(SaltError):
    """Salt is not of expected length"""


class SafetyMargin(Exception):
    """Class for exceptions raised when things are not actually errors, just not acceptably safe."""


class LowIterationCount(SafetyMargin):
    """CPU is cheap, security is not"""
