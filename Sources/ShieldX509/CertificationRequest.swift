//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/12/19.
//

import Foundation
import PotentASN1
import ShieldX500
import ShieldOID


public struct CertificationRequest: Equatable, Hashable, Codable {

  public var certificationRequestInfo: CertificationRequestInfo
  public var signatureAlgorithm: AlgorithmIdentifier
  public var signature: Data

  public init(certificationRequestInfo: CertificationRequestInfo, signatureAlgorithm: AlgorithmIdentifier, signature: Data) {
    self.certificationRequestInfo = certificationRequestInfo
    self.signatureAlgorithm = signatureAlgorithm
    self.signature = signature
  }

}


extension CertificationRequest: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.CertificationRequest }

}



// MARK: Schemas

public extension Schemas {

  static let CertificationRequest: Schema =
    .sequence([
      "certificationRequestInfo": CertificationRequestInfo,
      "signatureAlgorithm": AlgorithmIdentifier(SignatureAlgorithms),
      "signature": .bitString()
    ])

}
