//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/24/19.
//

import Foundation
import PotentASN1


public struct DistinguishedNameBuilder<Mapper: AttributeValueMapper> {

  public enum Error: Swift.Error {
    case unknownTypeName(name: String, style: NamingStyle)
  }

  public typealias RDN = [ATV]
  public typealias ATV = AttributeTypeAndValue<Mapper>

  public let style: NamingStyle
  public var rdns: RDNSequence<Mapper>

  public init(rdns: [RDN] = [], style: NamingStyle = .rfc4519) {
    self.style = style
    self.rdns = rdns
  }

  public func add(multiValued values: (typeName: String, value: String)...) throws -> Self {
    return try add(multiValued: values)
  }

  public func add(multiValued values: [(typeName: String, value: String)]) throws -> Self {

    var rdn = [(type: OID, value: AnyString)]()

    for (typeName, value) in values {
      guard let type = style.oid(fromName: typeName) else {
        throw Error.unknownTypeName(name: typeName, style: style)
      }
      rdn.append((type: type, value: AnyString(value)))
    }

    return add(multiValued: rdn)
  }

  public func add(multiValued values: (type: OID, value: AnyString)...) -> Self {
    return add(multiValued: values)
  }

  public func add(multiValued values: [(type: OID, value: AnyString)]) -> Self {
    let rdn = values.map { ATV(type: $0.type, value: $0.value) }
    return Self(rdns: self.rdns + [rdn], style: style)
  }

  public func add(_ value: String, forTypeName name: String) throws -> Self {
    guard let type = style.oid(fromName: name) else {
      throw Error.unknownTypeName(name: name, style: style)
    }
    return add(value, forType: type)
  }

  public func add(_ value: String, forType type: OID) -> Self {
    return add(AnyString(value), forType: type)
  }

  public func add(_ value: AnyString, forType type: OID) -> Self {
    return Self(rdns: self.rdns + [[ATV(type: type, value: value)]], style: style)
  }

  public func add(parsed string: String) throws -> Self {
    let parser = DistinguishedNameStringParser<Mapper>(style: style)
    let parsed = try parser.parse(string: string)
    return Self(rdns: parsed, style: style)
  }

  public static func parse(string: String, style: NamingStyle = .rfc4519) throws -> RDNSequence<Mapper> {
    return try Self(style: style).add(parsed: string).rdns
  }

}
