# ``ShieldSecurity``

Swift interface for Apple's `Security` Framework.

## Overview

`ShieldSecurity` provides extensions to security objects provided by the `Security` framework making them easier to
work with and in many cases adding capabilities.

One of the main goals of `ShieldSecurity` is to provide a common interface that is available on all Apple platforms 
including macOS, iOS, watchOS, and tvOS. This ensures that all the code handling specific platform differences are
isolated in the ShieldSecurity package and doesn't have to be handled in application code.

Another goal of SieldSecurity is to extend objects like `SecKey` and `SecCertificate` with easier interfaces and
more capabilities. To further this goal a couple small "new" types have been added to provided clean interfaces.

The following `Security` objects have notable extensions:

### SecKey

`SecKey` 's extensions provide the following platform agnostic capabilities:

* Sign/Verify
* Encrypt/Decrypt
* Saving/Loading/Deleting from Keychains
* DER format encoding/decoding 


### SecCertificate

`SecCertificate`'s extensions provide the following platform agnostic capabilities:

* Trust Validated Public Key
* Access to frequently used properties (issuer, subject)
* Access decoded Certificate (ShieldX509 `Certificate` type)
* Saving/Loading/Deleting from Keychains
* DER format encoding/decoding
* PEM loading/saving
