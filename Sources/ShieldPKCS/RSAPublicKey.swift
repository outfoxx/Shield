//
//  File.swift
//
//
//  Created by Kevin Wooten on 7/23/19.
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
      "publicExponent": .integer()
    ])

}
