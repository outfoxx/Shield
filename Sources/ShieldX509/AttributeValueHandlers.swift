//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/26/19.
//

import Foundation
import PotentASN1


public typealias UnknownAttributeValueHandler = SimpleAttributeValueHandler<ASN1>


public struct SimpleAttributeValueHandler<AttributeValue: Codable & Hashable>: AttributeValueHandler {

  public static func decode(from container: inout UnkeyedDecodingContainer) throws -> Any {
    return try container.decode(AttributeValue.self)
  }

  public static func encode(_ value: Any, to container: inout UnkeyedEncodingContainer) throws {
    try container.encode(value as! AttributeValue)
  }

  public static func equal(_ lhs: Any, _ rhs: Any) -> Bool {
    return (lhs as? AttributeValue) == (rhs as? AttributeValue)
  }

  public static func hash(_ value: Any, into hasher: inout Hasher) {
    guard let value = value as? AttributeValue else { fatalError("Invalid attribute value") }
    value.hash(into: &hasher)
  }

}
