# ``ShieldX500``

X.500 name composition, parsing and string conversion.

## Overview

X.500 naming objects required by ``ShieldX509``.

> Note: They exist in a separate namespace to more easily match the ASN.1 naming laid out in related RFCs.

### Name, NameBuilder & NamingStyle

The most noteworthy types for users are ``ShieldX500/DistinguishedNameBuilder`` and
``ShieldX500/DistinguishedNameStringComposer``.

> Note: ``ShieldX509/NameBuilder`` and ``ShieldX509/NameStringComposer`` are typealiases that provide the required
generic types and are easier to use for end users.

``ShieldX500/DistinguishedNameBuilder`` enables composing X.500 namesusing a number of method with the most user
friendly being using LDAP string representation algorithms defined in RFC2253 & later RFC4514. For example, strings
like `"test=CN"` can be parsed into proper X.500 name structures.

OID to string name conversion, and vice versa, can follow a few different schemes.  To allow users to control this
process the ``ShieldX500/NamingStyle`` protocol is provided and ``ShieldX500/DistinguishedNameBuilder`` can be adapted
to use a custom naming style.

Currently the following naming styles are provided:

* RFC4519
