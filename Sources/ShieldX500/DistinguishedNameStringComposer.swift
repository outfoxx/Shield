//
//  DistinguishedNameStringComposer.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct DistinguishedNameStringComposer<Mapper: AttributeValueMapper> {

  public enum Error: Swift.Error {
    case unsupportedAttributeType(OID)
    case attributeEncodingError(Swift.Error)
  }

  typealias RDN = RelativeDistinguishedName<Mapper>
  typealias ATV = AttributeTypeAndValue<Mapper>

  public let rdnStrings: [String]
  public let style: NamingStyle

  public init(rdnStrings: [String] = [], style: NamingStyle = .rfc4519) {
    self.rdnStrings = rdnStrings
    self.style = style
  }

  public var string: String {
    return rdnStrings.joined(separator: ",")
  }

  public func append(rdnSequence: RDNSequence<Mapper>) throws -> Self {

    var rdnStrings: [String] = self.rdnStrings

    for rdn in rdnSequence {
      rdnStrings.append(contentsOf: try append(rdn: rdn).rdnStrings)
    }

    return Self(rdnStrings: rdnStrings, style: style)
  }

  public func append(rdn: RelativeDistinguishedName<Mapper>) throws -> Self {

    var atvStrings: [String] = []

    for element in rdn {
      atvStrings.append(try Self.compose(type: element.type, value: element.value, style: style))
    }

    let rdnString = atvStrings.joined(separator: "+")

    return Self(rdnStrings: rdnStrings + [rdnString], style: style)
  }

  public func append(_ value: AttributeTypeAndValue<Mapper>) throws -> Self {
    return try append(value.value, forType: value.type)
  }

  public func append(_ value: Any, forType type: OID) throws -> Self {

    let atvString = try Self.compose(type: type, value: value, style: style)

    return Self(rdnStrings: [atvString], style: style)
  }

  public static func compose(_ rdnSequence: RDNSequence<Mapper>, style: NamingStyle = .rfc4519) throws -> String {
    return try Self(style: style).append(rdnSequence: rdnSequence).string
  }

  private static func compose(type: OID, value: Any, style: NamingStyle) throws -> String {
    return "\(stringOf(type: type, style: style))=\(try stringOf(value: value, forType: type))"
  }

  private static func stringOf(type: OID, style: NamingStyle) -> String {

    if let name = style.name(fromOID: type) {
      return name
    }

    return OID.dotOid(of: type)
  }

  private static func stringOf(value: Any, forType type: OID) throws -> String {
    let string: String

    if let value = value as? String {
      string = value
    }
    else if let value = value as? AnyString {
      string = value.storage
    }
    else {
      guard let valueEncoder = Mapper.encoder(forType: type) else {
        throw Error.unsupportedAttributeType(type)
      }
      do {
        string = String(try valueEncoder(value).flatMap { String($0, radix: 16) })
      }
      catch {
        throw Error.attributeEncodingError(error)
      }
    }

    var result = ""

    for char in string {
      switch char {
      case ",", "\"", "\\", "+", "=", "<", ">", ";":
        result.append("\\")
        fallthrough
      default:
        result.append(char)
      }
    }

    if let first = result.first, first == " " {
      result.insert("\\", at: result.startIndex)
    }
    if let last = result.last, last == " " {
      result.insert("\\", at: result.index(before: result.endIndex))
    }

    return result
  }

}
