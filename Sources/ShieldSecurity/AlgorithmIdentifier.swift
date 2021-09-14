//
//  AlgorithmIdentifier.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldCrypto
import ShieldOID
import ShieldPKCS
import ShieldX509

public extension AlgorithmIdentifier {

  enum Error: Swift.Error {
    case unsupportedAlgorithm
    case unsupportedECKeySize
  }

  init(digestAlgorithm: Digester.Algorithm, keyType: SecKeyType) throws {
    let signingAlgorithmID: OID
    switch keyType {

    case .rsa:

      switch digestAlgorithm {
      case .sha1:
        signingAlgorithmID = iso.memberBody.us.rsadsi.pkcs.pkcs1.sha1WithRSASignature.oid
      case .sha224:
        signingAlgorithmID = iso.memberBody.us.rsadsi.pkcs.pkcs1.sha224WithRSAEncryption.oid
      case .sha256:
        signingAlgorithmID = iso.memberBody.us.rsadsi.pkcs.pkcs1.sha256WithRSAEncryption.oid
      case .sha384:
        signingAlgorithmID = iso.memberBody.us.rsadsi.pkcs.pkcs1.sha384WithRSAEncryption.oid
      case .sha512:
        signingAlgorithmID = iso.memberBody.us.rsadsi.pkcs.pkcs1.sha512WithRSAEncryption.oid
      default:
        throw Error.unsupportedAlgorithm
      }

    case .ec:

      switch digestAlgorithm {
      case .sha1:
        signingAlgorithmID = iso.memberBody.us.ansix962.signatures.ecdsaWithSHA1.oid
      case .sha224:
        signingAlgorithmID = iso.memberBody.us.ansix962.signatures.ecdsaWithSHA2.ecdsaWithSHA224.oid
      case .sha256:
        signingAlgorithmID = iso.memberBody.us.ansix962.signatures.ecdsaWithSHA2.ecdsaWithSHA256.oid
      case .sha384:
        signingAlgorithmID = iso.memberBody.us.ansix962.signatures.ecdsaWithSHA2.ecdsaWithSHA384.oid
      case .sha512:
        signingAlgorithmID = iso.memberBody.us.ansix962.signatures.ecdsaWithSHA2.ecdsaWithSHA512.oid
      default:
        throw Error.unsupportedAlgorithm
      }
    }

    self.init(algorithm: signingAlgorithmID)
  }

  init(publicKey: SecKey) throws {
    switch try publicKey.keyType() {
    case .rsa:
      self.init(algorithm: iso.memberBody.us.rsadsi.pkcs.pkcs1.rsaEncryption.oid)

    case .ec:
      let curve: OID
      switch try publicKey.attributes()[kSecAttrKeySizeInBits as String] as? Int ?? 0 {
      case 192:
        // P-192, secp192r1
        curve = iso.memberBody.us.ansix962.curves.prime.prime192v1.oid
      case 256:
        // P-256, secp256r1
        curve = iso.memberBody.us.ansix962.curves.prime.prime256v1.oid
      case 384:
        // P-384, secp384r1
        curve = iso.org.certicom.curve.ansip384r1.oid
      case 521:
        // P-521, secp521r1
        curve = iso.org.certicom.curve.ansip521r1.oid
      default:
        throw Error.unsupportedECKeySize
      }

      self.init(
        algorithm: iso.memberBody.us.ansix962.keyType.ecPublicKey.oid,
        parameters: .objectIdentifier(curve.fields)
      )
    }
  }

}
