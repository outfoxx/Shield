//
//  RSAPublicKey.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct RSAPublicKey: Equatable, Hashable, Codable {

  public var modulus: ASN1.Integer
  public var publicExponent: ASN1.Integer

  public init(modulus: ASN1.Integer, publicExponent: ASN1.Integer) {
    self.modulus = modulus
    self.publicExponent = publicExponent
  }

}


extension RSAPublicKey: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.RSAPublicKey }

}



public extension Schemas {

  static let RSAPublicKey: Schema =
    .sequence([
      "modulus": .integer(),
      "publicExponent": .integer(),
    ])

}
