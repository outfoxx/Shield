//
//  RSAPrivateKey.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct RSAPrivateKey: Equatable, Hashable, Codable {

  public enum Version: Int, CaseIterable, Equatable, Hashable, Codable {
    case twoPrime = 0
    case multi = 1
  }

  public struct OtherPrimeInfo: Equatable, Hashable, Codable {
    public var prime: ASN1.Integer
    public var exponent: ASN1.Integer
    public var coefficient: ASN1.Integer
  }

  public var version: Version
  public var modulus: ASN1.Integer
  public var publicExponent: ASN1.Integer
  public var privateExponent: ASN1.Integer
  public var prime1: ASN1.Integer
  public var prime2: ASN1.Integer
  public var exponent1: ASN1.Integer
  public var exponent2: ASN1.Integer
  public var coefficient: ASN1.Integer
  public var otherPrimeInfos: [OtherPrimeInfo]?
}


extension RSAPrivateKey: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.RSAPrivateKey }

}



public extension Schemas {

  static let RSAPrivateKey: Schema =
    .sequence([
      "version": .version(.integer(allowed: 0 ..< 2)),
      "modulus": .integer(),
      "publicExponent": .integer(),
      "privateExponent": .integer(),
      "prime1": .integer(),
      "prime2": .integer(),
      "exponent1": .integer(),
      "exponent2": .integer(),
      "coefficient": .integer(),
      "otherPrimeInfos": .versioned(range: 1 ... 1, RSAPrivateKeyOtherPrimeInfos),
    ])

  static let RSAPrivateKeyOtherPrimeInfos: Schema =
    .sequenceOf(RSAPrivateKeyOtherPrimeInfo, size: .min(1))

  static let RSAPrivateKeyOtherPrimeInfo: Schema =
    .sequence([
      "prime": .integer(),
      "exponent": .integer(),
      "coefficient": .integer(),
    ])

}
