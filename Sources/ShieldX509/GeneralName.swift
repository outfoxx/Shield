//
//  GeneralName.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public typealias GeneralNames = [GeneralName]


public enum GeneralName: Equatable, Hashable, Tagged {
  case otherName(OtherName)
  case rfc822Name(String)
  case dnsName(String)
  case x400Address(ASN1)
  case directoryName(Name)
  case ediPartyName(EDIPartyName)
  case uniformResourceIdentifier(String)
  case ipAddress(Data)
  case registeredID(ObjectIdentifier)

  public init?(tag: ASN1.AnyTag, value: Any?) {
    switch ASN1.Tag.value(from: tag, in: .contextSpecific) {
    case 0:
      guard
        let values = value as? [ASN1],
        let name = try? ASN1Decoder(schema: Schemas.OtherName).decodeTree(OtherName.self, from: .sequence(values))
      else {
        return nil
      }
      self = .otherName(name)
    case 1:
      guard let value = value as? AnyString else { return nil }
      self = .rfc822Name(value.storage)
    case 2:
      guard let value = value as? AnyString else { return nil }
      self = .dnsName(value.storage)
    case 3:
      guard let value = value as? ASN1 else { return nil }
      self = .x400Address(value)
    case 4:
      guard
        let values = value as? [ASN1],
        let name = try? ASN1Decoder(schema: Schemas.Name).decodeTree(Name.self, from: .sequence(values))
      else {
        return nil
      }
      self = .directoryName(name)
    case 5:
      guard
        let values = value as? [ASN1],
        let name = try? ASN1Decoder(schema: Schemas.EDIPartyName).decodeTree(EDIPartyName.self, from: .sequence(values))
      else {
        return nil
      }
      self = .ediPartyName(name)
    case 6:
      guard let value = value as? AnyString else { return nil }
      self = .uniformResourceIdentifier(value.storage)
    case 7:
      guard let value = value as? Data else { return nil }
      self = .ipAddress(value)
    case 8:
      guard let value = value as? ObjectIdentifier else { return nil }
      self = .registeredID(value)
    default:
      return nil
    }
  }

  public var tag: ASN1.AnyTag {
    switch self {
    case .otherName: return 0
    case .rfc822Name: return 1
    case .dnsName: return 2
    case .x400Address: return 3
    case .directoryName: return 4
    case .ediPartyName: return 5
    case .uniformResourceIdentifier: return 6
    case .ipAddress: return 7
    case .registeredID: return 8
    }
  }

  public var value: Any? {
    switch self {
    case .otherName(let value): return value
    case .rfc822Name(let value): return value
    case .dnsName(let value): return value
    case .x400Address(let value): return value
    case .directoryName(let value): return value
    case .ediPartyName(let value): return value
    case .uniformResourceIdentifier(let value): return value
    case .ipAddress(let value): return value
    case .registeredID(let value): return value
    }
  }

  public func encode(schema: Schema) throws -> ASN1 {
    let encoder = ASN1Encoder(schema: schema)
    switch self {
    case .otherName(let value): return try encoder.encodeTree(value)
    case .rfc822Name(let value): return try encoder.encodeTree(value)
    case .dnsName(let value): return try encoder.encodeTree(value)
    case .x400Address(let value): return value
    case .directoryName(let value): return try encoder.encodeTree(value)
    case .ediPartyName(let value): return try encoder.encodeTree(value)
    case .uniformResourceIdentifier(let value): return try encoder.encodeTree(value)
    case .ipAddress(let value): return try encoder.encodeTree(value)
    case .registeredID(let value): return try encoder.encodeTree(value)
    }
  }
}



// MARK: Schemas

public extension Schemas {

  static let GeneralNames: Schema =
    .sequenceOf(GeneralName, size: .min(1))

  static let GeneralName: Schema =
    .choiceOf([
      .implicit(0, OtherName),
      .implicit(1, .string(kind: .ia5)),
      .implicit(2, .string(kind: .ia5)),
      .implicit(3, .any),
      .explicit(4, Name),
      .implicit(5, EDIPartyName),
      .implicit(6, .string(kind: .ia5)),
      .implicit(7, .octetString()),
      .implicit(8, .objectIdentifier()),
    ])

}

extension GeneralName: Codable {

  public init(from decoder: Decoder) throws {
    var container = try decoder.unkeyedContainer()
    let tag = try container.decode(UInt8.self)
    switch ASN1.Tag.value(from: tag, in: .contextSpecific) {
    case 0:
      self = .otherName(try container.decode(OtherName.self))

    case 1:
      self = .rfc822Name(try container.decode(String.self))

    case 2:
      self = .dnsName(try container.decode(String.self))

    case 3:
      self = .x400Address(try container.decode(ASN1.self))

    case 4:
      self = .directoryName(try container.decode(Name.self))

    case 5:
      self = .ediPartyName(try container.decode(EDIPartyName.self))

    case 6:
      self = .uniformResourceIdentifier(try container.decode(String.self))

    case 7:
      self = .ipAddress(try container.decode(Data.self))

    case 8:
      self = .registeredID(try container.decode(ObjectIdentifier.self))

    default:
      throw DecodingError.dataCorruptedError(in: container, debugDescription: "No matching tag")
    }
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.unkeyedContainer()
    switch self {
    case .otherName(let value):
      try container.encode(ASN1.Tag.tag(from: 0, in: .contextSpecific, constructed: true))
      try container.encode(value)

    case .rfc822Name(let value):
      try container.encode(ASN1.Tag.tag(from: 1, in: .contextSpecific, constructed: false))
      try container.encode(value)

    case .dnsName(let value):
      try container.encode(ASN1.Tag.tag(from: 2, in: .contextSpecific, constructed: false))
      try container.encode(value)

    case .x400Address(let value):
      try container.encode(ASN1.Tag.tag(from: 3, in: .contextSpecific, constructed: true))
      try container.encode(value)

    case .directoryName(let value):
      try container.encode(ASN1.Tag.tag(from: 4, in: .contextSpecific, constructed: true))
      try container.encode(value)

    case .ediPartyName(let value):
      try container.encode(ASN1.Tag.tag(from: 5, in: .contextSpecific, constructed: true))
      try container.encode(value)

    case .uniformResourceIdentifier(let value):
      try container.encode(ASN1.Tag.tag(from: 6, in: .contextSpecific, constructed: false))
      try container.encode(value)

    case .ipAddress(let value):
      try container.encode(ASN1.Tag.tag(from: 7, in: .contextSpecific, constructed: false))
      try container.encode(value)

    case .registeredID(let value):
      try container.encode(ASN1.Tag.tag(from: 8, in: .contextSpecific, constructed: false))
      try container.encode(value)
    }
  }

}
