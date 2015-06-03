**This file specifies which documents form the authoritative basis for the cryptographic primitives used and/or implemented within the Cryptoe project.**

***No cryptography code shall be added without an appropriate reference document, and where uncertainty may exist functions MUST reference source documents in docstrings.***

The goals of this approach:

- Security and trustworthiness of implementation
- Avoidance of hand-rolled crypto except where it actually simplifies or provably improves the implementation
- Easy identification of the source document behind any given algorithm, in case that algorithm should at a later date be revised or become suspect
- Easy avoidance of cryptographic primitives which the author does not wish to use, for whatever reason.


| Author(s) or Organization | Publication |
|:---:|:---:|
| **NIST** | **SP 800-38A**: *Recommendation for Block Cipher Modes of Operation: Methods and Techniques* |
| **NIST** | **SP 800-38F**: *Recommendation for Block Cipher Modes of Operation: Methods for Key Wrapping* |
| **NIST** | **SP 800-132**: *Recommendation for Password-Based Key Derivation Part 1: Storage Applications* |
| **Ferguson and Schneier** | *Practical Cryptography* |
