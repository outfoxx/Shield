//
//  AlgorithmIdentifier.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import ShieldCrypto
import ShieldOID
import ShieldX509


public extension AlgorithmIdentifier {

  enum Error: Swift.Error {
    case unsupportedAlgorithm
  }

  init(digestAlgorithm: Digester.Algorithm) throws {
    let signingAlgorithmID: OID
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

    self.init(algorithm: signingAlgorithmID, parameters: nil)
  }

  init(publicKey: SecKey) throws {
    switch try publicKey.keyType(class: kSecAttrKeyClassPublic) {
    case .RSA:
      self.init(algorithm: iso.memberBody.us.rsadsi.pkcs.pkcs1.rsaEncryption.oid, parameters: nil)

    default:
      fatalError("unsupported public key type")
    }
  }

}
