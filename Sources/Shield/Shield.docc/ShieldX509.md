# ``ShieldX509``

X.509 certificate & PKCS10 certification request generation and parsing.

## Overview

Provides easy generation and signing of PKCS10 ``ShieldX509/CertificationRequest``s (aka CSRs) and X.509
``ShieldX509/Certificate``s.

### Certificate and Certificate.Builder

X.509 Certificates can be generated programmatically using ``ShieldX509/Certificate`` or loaded/saved using
Swift's  `Codable` system.

``ShieldX509/Certificate/Builder`` provides an easy interface for generating certificates based on individual data or
from a provided ``ShieldX509/CertificationRequest``.

``ShieldX509/Certificate/Builder`` also provides easy methods for
signing generated certificates.

### CertificationRequest` and CertificationRequest.Builder

Certification requests can be generated programmatically using ``ShieldX509/CertificationRequest`` or loaded/saved
using Swift's  `Codable` system.

``ShieldX509/CertificationRequest/Builder`` provides an easy interface for generating requests based on only the
required data as well as provide a signed version.

### ASN.1
ASN.1 DER encoding/decoding is provided by [PotentASN1](https://github.com/outfoxx/PotentCodables) and can be used to
achieve interoperation with any standard X.509 facilities.  All of the objects provided by ShieldX509 work with
standard `Codable` encoders/decoders in addition to the specialized `ASN1Encoder`/`ASN1Decoder` provided by
`PotentASN1`.  

#### ASN.1 Schemas
 [PotentASN1](https://github.com/outfoxx/PotentCodables) requires schema information when encoding/decoding to resolve
ambiguities possible with ASN.1 when encoding in DER format.  All types in ShieldX509, ShieldX500 & ShieldPKCS provide
a schema with a matching name in the ``ShieldX509/Schemas`` psuedo-namespace. For example,
``ShieldX509/Certificate``'s schema is available in ``ShieldX509/Schemas/Certificate``. 
