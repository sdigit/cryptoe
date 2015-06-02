This file specifies which documents form the authoritative basis for the cryptographic primitives used and/or
implemented within the Cryptoe project.

All code in Cryptoe itself, insofar as it implements any function or method defined in one of these standards, MUST be
run side by side against another implementation to ensure identical outputs with identical inputs.

All code imported by Cryptoe MUST be reviewed to ensure that it follows the standard. Periodic review to ensure that
this is still the case SHOULD be undertaken when versions of imported packages change.

No cryptography code shall be added without an appropriate reference document, and where uncertainty may exist functions
MUST reference source documents in docstrings.

The goals of this approach:

1) Security and trustworthiness of implementation
2) Avoidance of hand-rolled crypto except where it actually simplifies or provably improves the implementation
3) Easy identification of the source document behind any given algorithm, in case that algorithm should at a later date
   be revised or become suspect [ref: withdrawn Dual-EC-DRBG controversy]
4) Easy avoidance of cryptographic primitives which the author does not wish to use, for whatever reason.


NIST SP 800-38A             Recommendation for Block Cipher Modes of Operation: Methods and Techniques
NIST SP 800-38F             Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping
NIST SP 800-132             Recommendation for Password-Based Key Derivation Part 1: Storage Applications
IETF RFC 2898               PKCS #5: Password-Based Cryptography Specification (Version 2.0)
Cryptography Engineering    Fortuna, SHAd256, Professional Paranoia
