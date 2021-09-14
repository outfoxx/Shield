//
//  AttributeValueHandlers.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct AnyStringAttributeValueHandler: AttributeValueHandler {

  public static let instance = AnyStringAttributeValueHandler()

  public func decode(from decoder: Decoder) throws -> Any {
    let container = try decoder.singleValueContainer()
    return try container.decode(AnyString.self)
  }

  public func encode(_ value: Any, to encoder: Encoder) throws {
    guard let value = value as? AnyString else { fatalError("Invalid attribute value") }
    var container = encoder.singleValueContainer()
    try container.encode(value)
  }

  public func equals(_ lhs: Any, _ rhs: Any) -> Bool {
    guard let lhs = lhs as? AnyString, let rhs = rhs as? AnyString else { fatalError("Invalid attribute value") }
    return lhs == rhs
  }

  public func hash(_ value: Any, into hasher: inout Hasher) {
    guard let value = value as? AnyString else { fatalError("Invalid attribute value") }
    value.hash(into: &hasher)
  }

}


public struct UnknownAttributeValueHandler: AttributeValueHandler {

  public static let instance = UnknownAttributeValueHandler()

  public func decode(from decoder: Decoder) throws -> Any {
    let container = try decoder.singleValueContainer()
    return try container.decode(ASN1.self)
  }

  public func encode(_ value: Any, to encoder: Encoder) throws {
    guard let value = value as? ASN1 else { fatalError("Invalid attribute value") }
    var container = encoder.singleValueContainer()
    try container.encode(value)
  }

  public func equals(_ lhs: Any, _ rhs: Any) -> Bool {
    guard let lhs = lhs as? ASN1, let rhs = rhs as? ASN1 else { fatalError("Invalid attribute value") }
    return lhs == rhs
  }

  public func hash(_ value: Any, into hasher: inout Hasher) {
    guard let value = value as? ASN1 else { fatalError("Invalid attribute value") }
    value.hash(into: &hasher)
  }

}
