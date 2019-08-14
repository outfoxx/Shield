//
//  File.swift
//  
//
//  Created by Kevin Wooten on 8/7/19.
//

import Foundation
import ShieldX509
import PotentASN1
import ShieldCrypto


public extension CertificationRequest.Builder {

  func publicKey(keyPair: SecKeyPair, usage keyUsage: KeyUsage? = nil) throws -> CertificationRequest.Builder {
    return try self.publicKey(keyPair.encodedPublicKey(),
                              algorithm: .init(publicKey: keyPair.publicKey),
                              usage: keyUsage)
  }

  func publicKey(publicKey: SecKey, usage keyUsage: KeyUsage? = nil) throws -> CertificationRequest.Builder {
    return try self.publicKey(publicKey.encode(class: kSecAttrKeyClassPublic),
                              algorithm: .init(publicKey: publicKey),
                              usage: keyUsage)
  }

  func build(signingKey: SecKey, digestAlgorithm: Digester.Algorithm) throws -> CertificationRequest {
    return try buildInfo().signed(using: signingKey, digestAlgorithm: digestAlgorithm)
  }

}

public extension CertificationRequestInfo {

  func signed(using signingKey: SecKey, digestAlgorithm: Digester.Algorithm) throws -> CertificationRequest {

    let signatureAlgorithm = try AlgorithmIdentifier(digestAlgorithm: digestAlgorithm)

    let infoData = try ASN1Encoder.encode(self)

    let signature = try signingKey.sign(data: infoData, digestAlgorithm: digestAlgorithm)

    return CertificationRequest(certificationRequestInfo: self,
                                signatureAlgorithm: signatureAlgorithm,
                                signature: signature)
  }

}
