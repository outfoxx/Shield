//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1
import PotentCodables


// MARK: Attribute

public struct Attribute {

  enum CodingKeys: CodingKey {
    case attrType
    case attrValues
  }

  public var attrType: ObjectIdentifier
  public var attrValues: [Any]

  public init(attrType: ObjectIdentifier, attrValues: [Any]) {
    self.attrType = attrType
    self.attrValues = attrValues
  }

}


// MARK: Attributes

public protocol AttributeValue {
  static var attributeType: ObjectIdentifier { get }
  static var attributeHandler: AttributeValueHandler.Type { get }
}

public protocol SingleAttributeValue: AttributeValue {}


public protocol AttributeValueHandler {
  static func encode(_ value: Any, to container: inout UnkeyedEncodingContainer) throws
  static func decode(from container: inout UnkeyedDecodingContainer) throws -> Any
  static func hash(_ value: Any, into: inout Hasher)
  static func equal(_ a: Any, _ b: Any) -> Bool
}

public protocol AttributeValuesHandler {
  static func handler(for type: ObjectIdentifier) -> AttributeValueHandler.Type
}

public struct Attributes<Handler: AttributeValuesHandler>: Equatable, Hashable, Codable {

  public enum Error: Swift.Error {
    case invalidElement
    case singleValueRequired
  }

  private var storage: [Attribute]

  public init() {
    self.storage = []
  }

  public func all<AV: AttributeValue>(_ type: AV.Type) throws -> [[AV]] {
    var found: [[AV]] = []
    for attribute in storage {
      if attribute.attrType == AV.attributeType {
        guard let attrValues = attribute.attrValues as? [AV] else {
          throw Error.invalidElement
        }
        found.append(attrValues)
      }
    }
    return found
  }

  public func all<AV: SingleAttributeValue>(_ type: AV.Type) throws -> [AV] {
    var found: [AV] = []
    for attribute in storage {
      if attribute.attrType == AV.attributeType {
        guard let attrValues = attribute.attrValues as? [AV] else {
          throw Error.invalidElement
        }
        guard attrValues.count == 1 else {
           throw Error.singleValueRequired
        }
        found.append(attrValues[0])
      }
    }
    return found
  }

  public func first<AV: AttributeValue>(_ type: AV.Type) throws -> [AV]? {
    for attribute in storage {
      if attribute.attrType == AV.attributeType {
        guard let attrValues = attribute.attrValues as? [AV] else {
          fatalError("Attribute's attrValues contains invalid elements")
        }
        return attrValues
      }
    }
    return nil
  }

  public func first<AV: SingleAttributeValue>(_ type: AV.Type) throws -> AV? {
    for attribute in storage {
      if attribute.attrType == AV.attributeType {
        guard let attrValues = attribute.attrValues as? [AV] else {
          throw Error.invalidElement
        }
        guard attrValues.count == 1 else {
          throw Error.singleValueRequired
        }
        return attrValues[0]
      }
    }
    return nil
  }

  public mutating func append<AV: AttributeValue>(_ values: [AV]) {
    storage.append(Attribute(attrType: AV.attributeType, attrValues: values))
  }

  public mutating func append<AV: SingleAttributeValue>(_ value: AV) {
    storage.append(Attribute(attrType: AV.attributeType, attrValues: [value]))
  }

  public mutating func append(type: ObjectIdentifier, values: [ASN1]) {
    storage.append(Attribute(attrType: type, attrValues: values))
  }

  public mutating func remove<AV: AttributeValue>(_ type: AV.Type) {
    storage = storage.filter { $0.attrType != AV.attributeType }
  }

}

extension Attributes: Collection, BidirectionalCollection, RandomAccessCollection {}



// MARK: Schemas

public extension Schemas {

  static func Attributes(_ ioSet: Schema.DynamicMap, allowUnknownTypes: Bool = false) -> Schema {
    .setOf(Attribute(ioSet, allowUnknownTypes: allowUnknownTypes))
  }

  static func Attribute(_ ioSet: Schema.DynamicMap, allowUnknownTypes: Bool) -> Schema {
    .sequence([
      "attrType": .type(.objectIdentifier()),
      "attrValues": .setOf(.dynamic(allowUnknownTypes: allowUnknownTypes, ioSet))
    ])
  }

}


// MARK: Attributes Conformances

extension Attributes {

  public init(from decoder: Decoder) throws {
    var container = try decoder.unkeyedContainer()
    var attrs = [Attribute]()
    for _ in 0 ..< (container.count ?? 0) {
      let attrContainer = try container.nestedContainer(keyedBy: Attribute.CodingKeys.self)
      let attrType = try attrContainer.decode(ObjectIdentifier.self, forKey: .attrType)
      let attrHandler = Handler.handler(for: attrType)
      var attrValuesContainer = try attrContainer.nestedUnkeyedContainer(forKey: .attrValues)
      var attrValues = [Any]()
      for _ in 0 ..< (attrValuesContainer.count ?? 0) {
        let attrValue = try attrHandler.decode(from: &attrValuesContainer)
        attrValues.append(attrValue)
      }
      attrs.append(.init(attrType: attrType, attrValues: attrValues))
    }
    self.storage = attrs
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.unkeyedContainer()
    for attr in storage {
      var attrContainer = container.nestedContainer(keyedBy: Attribute.CodingKeys.self)
      try attrContainer.encode(attr.attrType, forKey: .attrType)
      let attrHandler = Handler.handler(for: attr.attrType)
      var attrValuesContainer = attrContainer.nestedUnkeyedContainer(forKey: .attrValues)
      for attrValue in attr.attrValues {
        try attrHandler.encode(attrValue, to: &attrValuesContainer)
      }
    }
  }

  public func hash(into hasher: inout Hasher) {
    for attr in storage {
      hasher.combine(attr.attrType)
      let attrHandler = Handler.handler(for: attr.attrType)
      for value in attr.attrValues {
        attrHandler.hash(value, into: &hasher)
      }
    }
  }

  public static func ==(_ lhs: Attributes, _ rhs: Attributes) -> Bool {
    guard lhs.storage.count == rhs.storage.count else { return false }
    return zip(lhs.storage, rhs.storage).allSatisfy { l, r in
      guard l.attrType == r.attrType && l.attrValues.count == r.attrValues.count else { return false }
      let attrHandler = Handler.handler(for: l.attrType)
      return zip(l.attrValues, r.attrValues).allSatisfy { lv, rv in attrHandler.equal(lv, rv) }
    }
  }

}

extension Attributes {

  public typealias Index = Array<Attribute>.Index

  public typealias Iterator = Array<Attribute>.Iterator

  public var startIndex: Index { storage.startIndex }
  public var endIndex: Index { storage.endIndex }

  public __consuming func makeIterator() -> Iterator {
    return storage.makeIterator()
  }

  public subscript(position: Index) -> Attribute {
    get { storage[position] }
  }

}
