//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1
import PotentCodables
import ShieldOID


public protocol AttributeValueHandler {
  func decode(from decoder: Decoder) throws -> Any
  func encode(_ value: Any, to encoder: Encoder) throws
  func equals(_ lhs: Any, _ rhs: Any) -> Bool
  func hash(_ value: Any, into hasher: inout Hasher)
}


public protocol AttributeValueMapper {
  static func handler(forType type: ObjectIdentifier) -> AttributeValueHandler?

  typealias ValueEncoder = (Any) throws -> Data
  static func encoder(forType type: ObjectIdentifier) -> ValueEncoder?

  typealias ValueDecoder = (Data) throws -> Any?
  static func decoder(forType type: ObjectIdentifier) -> ValueDecoder?
}


public struct AttributeTypeAndValue<Mapper: AttributeValueMapper> {

  public var type: ObjectIdentifier
  public var value: Any

  public init(type: ObjectIdentifier, value: Any) {
    self.type = type
    self.value = value
  }

}


extension AttributeTypeAndValue: CustomStringConvertible, CustomDebugStringConvertible {

  public var description: String {
    return "\(type)=\(value)"
  }

  public var debugDescription: String {
    return "\(String(reflecting: type))=\(String(reflecting: value))"
  }

}


extension AttributeTypeAndValue: Equatable, Hashable, Codable {

  enum CodingKeys: CodingKey {
    case type
    case value
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    type = try container.decode(ObjectIdentifier.self, forKey: .type)
    guard let handler = Mapper.handler(forType: type) else { fatalError("Unsupported attribute type") }
    value = try handler.decode(from: KeyedNestedDecoder(key: .value, container: container, decoder: decoder))
  }

  public func encode(to encoder: Encoder) throws {
    guard let handler = Mapper.handler(forType: type) else { fatalError("Unsupported attribute type") }

    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(type, forKey: .type)
    try handler.encode(value, to: KeyedNestedEncoder(key: .value, container: container, encoder: encoder))
  }

  public func hash(into hasher: inout Hasher) {
    guard let handler = Mapper.handler(forType: type) else { fatalError("Unsupported attribute type") }
    hasher.combine(type)
    handler.hash(value, into: &hasher)
  }

  public static func ==(lhs: AttributeTypeAndValue, rhs: AttributeTypeAndValue) -> Bool {
    guard lhs.type == rhs.type else { return false }
    guard let handler = Mapper.handler(forType: lhs.type) else { fatalError("Unsupported attribute type") }
    return handler.equals(lhs.value, rhs.value)
  }

}



public extension Schemas {

  static func AttributeTypeAndValue(_ ioSet: Schema.DynamicMap, allowUnknownTypes: Bool) -> Schema {
    .sequence([
      "type": .type(.objectIdentifier()),
      "value": .dynamic(allowUnknownTypes: allowUnknownTypes, ioSet)
    ])
  }

}
