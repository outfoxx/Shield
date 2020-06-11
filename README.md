# 🛡 Shield
[![Build Status](https://travis-ci.org/outfoxx/Shield.svg?branch=master)](https://travis-ci.org/outfoxx/Shield)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/outfoxx/Shield)

## Security library covering Cryptography, Hashing, HMAC, Random, PBKDF, PKCS, X509, PKCS10

Shield is split into a number of libraries, each focusing on specific capabililties:

| Library                           |                                                             |
|-----------------------------------|-------------------------------------------------------------|
| [ShieldSecurity](#ShieldSecurity) | Swift interface for Apple's `Security` framework            |
| [ShieldCrypto](#ShieldCrypto)     | Swift interface for `CommonCrypto`                          |
| [ShieldX509](#ShieldX509)         | X.509 Certificate and PKCS10 CertificationRequest Framework |
| [ShieldX500](#ShieldX500)         | X.500 Naming Framework for [ShieldX509](#ShieldX509)        |
| [ShieldOID](#ShieldOID)           | OID Naming Framework for [ShieldX509](#ShieldX509)          |
| [ShieldPKCS](#ShieldPKCS)         | PKCS Framework for [ShieldX509](#ShieldX509)                |

## ShieldSecurity
### Swift interface for Apple's Security Framework

ShieldSecurity provides extensions to security objects provided by the `Security` framework making them easier to work with and
in many cases adding capabilities.

One of the main goals of ShieldSecurity is to provide a common interface that is available on all Apple platforms including macOS,
iOS, watchOS, and tvOS. This ensures that all the code handling specific platform differences are isolated in the ShieldSecurity package
and doesn't have to be handled in application code.

Another goal of SieldSecurity is to extend objects like `SecKey`,  `SecCertificate` with easier interfaces and more capabilities. To
further this goal a couple small "new" types have been added to provided clean interfaces.

The following type(s) have been added:

#### SecKeyPair

`SecKeyPair` provides an efficient interface to work with pairs (public and private) of asymmetric `SecKey` s. The following can be 
achieved using `SecKeyPair`:

* Key Pair Generation
* Saving/Loading/Deleting from Keychains
* Export/Import using PBKDF passphrase generated symmetric key
* DER format encoding/decoding 
* Certificate/KeyPair matching


The following `Security` objects have notable extensions:

####  SecKey

`SecKey` 's extensions provide the following platform agnostic capabilities:

* Sign/Verify
* Encrypt/Decrypt
* Saving/Loading/Deleting from Keychains
* DER format encoding/decoding 


####  SecCertificate

`SecCertificate`'s extensions provide the following platform agnostic capabilities:

* Trust Validated Public Key
* Access to frequently used properties (issuer, subject)
* Access decoded Certificate (ShieldX509 `Certificate` type)
* Saving/Loading/Deleting from Keychains
* DER format encoding/decoding
* PEM loading/saving


## ShieldCrypto
### Swift interface for `CommonCrypto`

Prior to Swift 5 no module-map was available for CommonCrypto which made its use cumbersome. In our previous library we provided
Objective-C wrappers to easily bridge the gap.  Now that Swift 5 includes the module-map we've turned our attention to providing a
proper Swift-centric interface to CommonCrypto facilities.

Most, if not all, of the CommonCrypto interfaces are exposed.

_**NOTE**_: No Cryptography algorithms are implemented in ShieldCrypto, it relies upon system provided implementations only.

### Cryptor
`Cryptor` provides access to system provided encryption/decryption algorithms with streaming and static data interfaces.

Supported Algorithms:
* AES
* DES
* 3DES
* CAST
* RC2
* RC4
* Blowfish

### Digester
`Digester` provides access to system provided hashing algorithms with streaming and static data interfaces.

Supported Algorithms:
* MD2
* MD4
* MD5
* SHA1
* SHA224
* SHA256
* SHA384
* SHA512

### HMAC
`HMAC` provides access to system provided hash based message authentication with streaming and static data interfaces.

Supported Hash Algorithms:
* MD5
* SHA1
* SHA224
* SHA256
* SHA384
* SHA512

### PBKDF
`PBKDF` provides access to the system provided password based key derivation algorithms.

Supported Algorithms:
* PBKD2

### Random
`Random` provides access to the system provided cryptographic random number generator.


## ShieldX509
### X.509 Certificate and PKCS10 CertificationRequest Framework

ShieldX509 provides easy generation and signing of PKCS10 `CertificationRequest`s (aka CSRs) and X.509 `Certificate`s.

### `Certificate` and `Certificate.Builder`
Certificates can be generated programmatically or loaded/saved using Swift's  `Codable` system.  The `Builder` provides an easy
interface for generating certificates based on individual data or from a provided `CertificationRequest`.  `Builder` also provides
easy methods for signing generated certificates.

### `CertificationRequest` and `CertificationRequest.Builder`
Certification requests can be generated programmatically or loaded/saved using Swift's  `Codable` system.  The `Builder` provides an
easy interface for generating requests based on only the required data as well as provided a signed version.

### ASN.1
ASN.1 DER encoding/decoding is provided by [PotentASN1](https://github.com/outfoxx/PotentCodables) and can be used to achieve
interoperation with any standard X.509 facilities.  All of the objects provided by ShieldX509 work with standard `Codable` 
encoders/decoders in addition to the specialized `ASN1Encoder`/`ASN1Decoder` provided by `PotentASN1`.  

#### ASN.1 Schemas
PotentASN1 requires schema information when encoding/decoding to resolve ambiguities possible with ASN.1 when encoding in
DER format.  All types in ShieldX509, ShieldX500 & ShieldPKCS provide a schema with a matching name in the `Schemas`
psuedo-namespace. For example, `Certificate`'s schema is available in `Schemas.Certificate`. 


## ShieldX500
### X.500 Naming Framework for [ShieldX509](#ShieldX509)

Provides X.500 naming objects required by `ShieldX509`. They exist in a separate namespace to more easily match the ASN.1 naming
laid out in related RFCs.

### `Name`, `NameBuilder` & `NamingStyle`
ShieldX500 does provide two noteworth types, `Name` and `NameBuilder`.  They provide interfaces for parsing/composing X.500 names
using LDAP string representation algorithms defined in RFC2253 & later RFC4514. For example, strings like `"test=CN"` can be parsed
into proper X.500 name structures.

OID to string name conversion, and vice versa, can follow a few different schemes.  To allow users to control this process the 
`NamingStyle` protocol is provided and `NameBuilder` can be adapted to use a custom naming style.  Currently the following naming
styles are provided:

  * RFC4519


  ## ShieldOID
  ### OID Naming Framework for [ShieldX509](#ShieldX509)

  Provides commonly used OIDs as static names in Swift and via string parsing.  While many of the OIDs used in X.500, X.509 and
  PKCS#10 are provided by `ShieldOID` due to the large nature of the OID library not all are provided.


## ShieldPKCS
### PKCS Framework for [ShieldX509](#ShieldX509)

Provide PKCS objects (e.g. RSAPublicKey, ECPublicKey) objects required by `ShieldX509`. They exist in a separate namespace to 
more easily match the ASN.1 naming laid out in related RFCs.
