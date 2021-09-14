//
//  Certificate.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import BigInt
import Foundation
import PotentASN1
import ShieldX500


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
      "signatureAlgorithm": algorithmIdentifier(SignatureAlgorithms),
      "signature": .bitString(),
    ])

}
