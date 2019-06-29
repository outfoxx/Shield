//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/14/19.
//

import Foundation
import PotentASN1
import ShieldX500
import BigInt


public struct Certificate: Equatable, Hashable, Codable {

  public var tbsCertificate: TBSCertificate
  public var signatureAlgorithm: AlgorithmIdentifier
  public var signature: Data

  public init(tbsCertificate: TBSCertificate, signatureAlgorithm: AlgorithmIdentifier, signature: Data) {
    self.tbsCertificate = tbsCertificate
    self.signatureAlgorithm = signatureAlgorithm
    self.signature = signature
  }
  
}


extension Certificate: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.Certificate }

}



// MARK: Schemas

public extension Schemas {

  static let Certificate: Schema =
    .sequence([
      "tbsCertificate": TBSCertificate,
      "signatureAlgorithm": AlgorithmIdentifier(SignatureAlgorithms),
      "signature": .bitString()
    ])

}
