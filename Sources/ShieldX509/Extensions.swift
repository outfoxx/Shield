//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1
import ShieldOID


// MARK: Extension

public struct Extension: Equatable, Hashable, Codable {

  public var extnID: ObjectIdentifier
  public var critical: Bool
  public var extnValue: Data

  public init(extnId: ObjectIdentifier, critical: Bool, extnValue: Data) {
    self.extnID = extnId
    self.critical = critical
    self.extnValue = extnValue
  }
}

// MARK: Extensions

public struct Extensions: Equatable, Hashable, Codable, SingleAttributeValue {

  public enum Error: Swift.Error {
    case invalidValue
  }

  public static var attributeType = iso.memberBody.us.rsadsi.pkcs.pkcs9.extensionRequest.oid
  public static var attributeHandler: AttributeValueHandler.Type = SimpleAttributeValueHandler<Extensions>.self

  private var storage: [Extension]

  public init() {
    self.storage = []
  }

  public func all<Value: ExtensionValue>(_ type: Value.Type) throws -> [Value] {
    return try storage.filter { $0.extnID == Value.extensionID }.map {
      return try ASN1Decoder.decode(Value.self, from: $0.extnValue)
    }
  }

  public func first<Value: ExtensionValue>(_ type: Value.Type) throws -> Value? {
    guard let found = storage.first(where: { $0.extnID == Value.extensionID }) else { return nil }
    return try ASN1Decoder.decode(Value.self, from: found.extnValue)
  }

  public mutating func append(id: ObjectIdentifier, isCritical: Bool, value: Data) {
    append(Extension(extnId: id, critical: isCritical, extnValue: value))
  }

  public mutating func append(_ element: Extension) {
    storage.append(element)
  }

  public mutating func append<Value: ExtensionValue>(value: Value) throws {
    let valueData = try ASN1Encoder.encode(value)
    append(id: Value.extensionID, isCritical: value.isCritical, value: valueData)
  }

  public mutating func remove<Value: ExtensionValue>(_ type: Value.Type) {
    remove(id: Value.extensionID)
  }

  public mutating func remove(id: ObjectIdentifier) {
    storage = storage.filter { $0.extnID != id }
  }

  public mutating func replace(_ element: Extension) {
    remove(id: element.extnID)
    append(element)
  }

  public mutating func replace<Value: ExtensionValue>(value: Value) throws {
    remove(id: Value.extensionID)
    append(id: Value.extensionID, isCritical: value.isCritical, value: try ASN1Encoder.encode(value))
  }

  public mutating func replaceAll<S>(_ elements: S) where S: Sequence, S.Element == Extension {
    for element in elements {
      replace(element)
    }
  }

}

extension Extensions: ExpressibleByArrayLiteral {}
extension Extensions: Collection, BidirectionalCollection, RandomAccessCollection {}



// MARK: Schemas

public extension Schemas {

  static let Extensions: Schema =
    .sequenceOf(Extension, size: .min(1))

  static let Extension: Schema =
    .sequence([
      "extnID": .objectIdentifier(),
      "critical": .boolean(default: false),
      "extnValue": .octetString()
    ])

}


// MARK: Extensions Conformances

extension Extensions {

  public init(from decoder: Decoder) throws {
    var container = try decoder.unkeyedContainer()
    var extensions: [Extension] = []
    for _ in 0 ..< (container.count ?? 0) {
      extensions.append(try container.decode(Extension.self))
    }
    self.storage = extensions
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.unkeyedContainer()
    for extension_ in storage {
      try container.encode(extension_)
    }
  }

}


extension Extensions {

  public typealias Index = Array<Extension>.Index
  public typealias Iterator = Array<Extension>.Iterator

  public var startIndex: Index { storage.startIndex }
  public var endIndex: Index { storage.endIndex }

  public __consuming func makeIterator() -> Iterator {
    return storage.makeIterator()
  }

  public init(arrayLiteral elements: Extension...) {
    self.storage = elements
  }

  public subscript(position: Index) -> Extension {
    get { storage[position] }
  }

}
