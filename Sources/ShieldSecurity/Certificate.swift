//
//  Certificate.swift
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
import ShieldX509


public extension Certificate.Builder {

  func publicKey(keyPair: SecKeyPair, usage keyUsage: KeyUsage? = nil) throws -> Certificate.Builder {
    return try publicKey(
      keyPair.encodedPublicKey(),
      algorithm: .init(publicKey: keyPair.publicKey),
      usage: keyUsage
    )
  }

  func publicKey(publicKey: SecKey, usage keyUsage: KeyUsage? = nil) throws -> Certificate.Builder {
    return try self.publicKey(
      publicKey.encode(),
      algorithm: .init(publicKey: publicKey),
      usage: keyUsage
    )
  }

  func build(signingKey: SecKey, digestAlgorithm: Digester.Algorithm) throws -> Certificate {

    let signatureAlgorithm = try AlgorithmIdentifier(digestAlgorithm: digestAlgorithm, keyType: signingKey.keyType())

    let tbsCertificate = try buildInfo(signatureAlgorithm: signatureAlgorithm)

    let signature = try signingKey.sign(data: tbsCertificate.encoded(), digestAlgorithm: digestAlgorithm)

    return Certificate(tbsCertificate: tbsCertificate, signatureAlgorithm: signatureAlgorithm, signature: signature)
  }

}


public extension Certificate {

  func sec() throws -> SecCertificate? {
    return try SecCertificateCreateWithData(nil, encoded() as CFData)
  }

}
