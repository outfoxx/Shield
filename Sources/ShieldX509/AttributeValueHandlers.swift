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


public typealias UnknownAttributeValueHandler = SimpleAttributeValueHandler<ASN1>


public struct SimpleAttributeValueHandler<AttributeValue: Codable & Hashable>: AttributeValueHandler {

  public static func decode(from container: inout UnkeyedDecodingContainer) throws -> Any {
    return try container.decode(AttributeValue.self)
  }

  public static func encode(_ value: Any, to container: inout UnkeyedEncodingContainer) throws {
    guard let value = value as? AttributeValue else { fatalError("Invalid attribute value") }
    try container.encode(value)
  }

  public static func equal(_ lhs: Any, _ rhs: Any) -> Bool {
    return (lhs as? AttributeValue) == (rhs as? AttributeValue)
  }

  public static func hash(_ value: Any, into hasher: inout Hasher) {
    guard let value = value as? AttributeValue else { fatalError("Invalid attribute value") }
    value.hash(into: &hasher)
  }

}
