//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/23/19.
//

import Foundation
import PotentASN1


public struct RSAPrivateKey: Equatable, Hashable, Codable {

  public enum Version: Int, CaseIterable, Equatable, Hashable, Codable {
    case twoPrime = 0
    case multi = 1
  }

  public struct OtherPrimeInfo: Equatable, Hashable, Codable {
    public var prime: Integer
    public var exponent: Integer
    public var coefficient: Integer
  }

  public var version: Version
  public var modulus: Integer
  public var publicExponent: Integer
  public var privateExponent: Integer
  public var prime1: Integer
  public var prime2: Integer
  public var exponent1: Integer
  public var exponent2: Integer
  public var coefficient: Integer
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
      "otherPrimeInfos":  .versioned(range: 1...1, RSAPrivateKeyOtherPrimeInfos)
    ])

  static let RSAPrivateKeyOtherPrimeInfos: Schema =
    .sequenceOf(RSAPrivateKeyOtherPrimeInfo, size: .min(1))

  static let RSAPrivateKeyOtherPrimeInfo: Schema =
    .sequence([
      "prime": .integer(),
      "exponent": .integer(),
      "coefficient": .integer()
    ])

}
