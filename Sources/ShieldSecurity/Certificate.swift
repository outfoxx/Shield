//
//  File.swift
//  
//
//  Created by Kevin Wooten on 8/8/19.
//

import Foundation
import ShieldX509
import PotentASN1
import ShieldCrypto
import ShieldOID


public extension Certificate.Builder {

  func publicKey(keyPair: SecKeyPair, usage keyUsage: KeyUsage? = nil) throws -> Certificate.Builder {
    return try self.publicKey(keyPair.encodedPublicKey(),
                              algorithm: .init(publicKey: keyPair.publicKey),
                              usage: keyUsage)
  }

  func publicKey(publicKey: SecKey, usage keyUsage: KeyUsage? = nil) throws -> Certificate.Builder {
    return try self.publicKey(publicKey.encode(class: kSecAttrKeyClassPublic),
                              algorithm: .init(publicKey: publicKey),
                              usage: keyUsage)
  }

  func build(signingKey: SecKey, digestAlgorithm: Digester.Algorithm) throws -> Certificate {

    let signatureAlgorithm = try AlgorithmIdentifier(digestAlgorithm: digestAlgorithm)

    let tbsCertificate = try buildInfo(signatureAlgorithm: signatureAlgorithm)

    let signature = try signingKey.sign(data: tbsCertificate.encoded(), digestAlgorithm: digestAlgorithm)

    return Certificate(tbsCertificate: tbsCertificate, signatureAlgorithm: signatureAlgorithm, signature: signature)
  }

}
