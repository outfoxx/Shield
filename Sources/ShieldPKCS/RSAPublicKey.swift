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

  public var modulus: Integer
  public var publicExponent: Integer

  public init(modulus: Integer, publicExponent: Integer) {
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
