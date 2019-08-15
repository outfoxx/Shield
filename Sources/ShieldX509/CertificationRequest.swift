//
//  CertificationRequest.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldOID
import ShieldX500


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
      "signature": .bitString(),
    ])

}
