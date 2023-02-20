# ``Shield``

Security library covering Cryptography, Hashing, HMAC, Random, PBKDF, PKCS, X509, & PKCS10.

## Overview

Shield is split into a number of libraries, each focusing on specific capabililties:

| Library             |                                                                           |
|---------------------|---------------------------------------------------------------------------|
| ``ShieldSecurity``  | Swift interface for Apple's `Security` Framework.                         |
| ``ShieldCrypto``    | Swift interface for `CommonCrypto`.                                       |
| ``ShieldX509``      | X.509 certificate & PKCS10 certification request generation and parsing.  |
| ``ShieldX500``      | X.500 name composition, parsing and string conversion.                    |
| ``ShieldOID``       | Common OID definitions and conversions.                                   |
| ``ShieldPKCS``      | Public Key Cryptograpgy Standard (PKCS) types for ``ShieldX509``.         |


## Topics

### ShieldSecurity

``ShieldSecurity`` is mostly comprised of extensions to `Security` types like `SecCertificate` and `SecKey`.

- ``ShieldSecurity/SecKeyPair``

### ShieldCrypto

- ``ShieldCrypto/Cryptor``
- ``ShieldCrypto/HMAC``
- ``ShieldCrypto/PBKDF``
- ``ShieldCrypto/Random``

#### Digest Algorithms

- ``ShieldCrypto/SHA1Digester``
- ``ShieldCrypto/SHA224Digester``
- ``ShieldCrypto/SHA256Digester``
- ``ShieldCrypto/SHA384Digester``
- ``ShieldCrypto/SHA512Digester``

### ShieldX509

- ``ShieldX509/Certificate``
- ``ShieldX509/Certificate/Builder``
- ``ShieldX509/CertificationRequest``
- ``ShieldX509/CertificationRequest/Builder``
- ``ShieldX509/NameBuilder``

#### Supported Extensions

- ``ShieldX509/BasicConstraints``
- ``ShieldX509/KeyUsage``
- ``ShieldX509/ExtKeyUsage``
- ``ShieldX509/SubjectKeyIdentifier``
- ``ShieldX509/AuthorityKeyIdentifier``
- ``ShieldX509/SubjectAltName``
- ``ShieldX509/IssuerAltName``

### ShieldX500

- ``ShieldX500/DistinguishedNameBuilder``
- ``ShieldX500/DistinguishedNameStringComposer``
- ``ShieldX500/DistinguishedNameStringParser``
- ``ShieldX500/RFC4519Style``

### ShieldOID

- ``ShieldOID/iso_itu``
- ``ShieldOID/iso``
- ``ShieldOID/itu``
