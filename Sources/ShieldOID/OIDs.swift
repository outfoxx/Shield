//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/23/19.
//

import Foundation
import PotentASN1


public typealias OID = ObjectIdentifier

extension OID: CustomDebugStringConvertible {

  public var debugDescription: String {
    return Self.asn1Name(of: self) ?? Self.dotOid(of: self)
  }

}


public protocol OIDRef {
  var oid: OID { get }
}


public extension OIDRef where Self: RawRepresentable & CaseIterable, RawValue == OID {
  var oid: OID { rawValue }
  var asn1: ASN1 { .objectIdentifier(rawValue.fields) }
}


public extension OID {

  fileprivate static let roots: [OIDBranch.Type] = [itu.self, iso.self, iso_itu.self]

  private static func branches<FC: Collection, NC: Collection>(fields: FC, nodes: NC) -> [OIDNode.Type]
    where FC.Element == UInt64, NC.Element == OIDNode.Type {
      for node in nodes {
        guard fields.first == node.id else { continue }

        if fields.count == 1 { return [node] }

        if let branch = node as? OIDBranch.Type {
          return [node] + branches(fields: fields.dropFirst(), nodes: branch.children)
        }
        return [node]
      }
      return []
  }

  private static func tree(of oid: OID) -> [(id: UInt64, name: String)]? {
    let tree = Self.branches(fields: oid.fields, nodes: roots)
    if tree.count == oid.fields.count {
      // Full match (non leaf)
      return tree.map { ($0.id, $0.names.first!) }
    }
    else if tree.count != oid.fields.count - 1 {
      // partial (aka non-match)
      return nil
    }

    guard
      let leafType = tree.last as? OIDLeaf.Type,
      let leaf = leafType.all.first(where: { $0.oid == oid })
    else {
      return nil
    }

    return tree.map { ($0.id, $0.names.first!) } + [(oid.fields.last!, String(describing: leaf))]
  }

  static func name(of oid: OID) -> String {
    return iriName(of: oid) ?? dotOid(of: oid)
  }

  static func dotOid(of oid: OID) -> String {
    return oid.fields.map { String($0) }.joined(separator: ".")
  }

  static func iriName(of oid: OID) -> String? {
    guard let names = tree(of: oid) else { return nil }
    return "/" + names.map { $0.name }.joined(separator: "/")
  }

  static func asn1Name(of oid: OID) -> String? {
    guard let names = tree(of: oid) else { return nil }
    return "{" + names.map { "\($0.name)(\($0.id))" }.joined(separator: " ") + "}"
  }

}

internal protocol OIDNode {
  static var id: UInt64 { get }
  static var names: [String] { get }
}

internal protocol OIDBranch: OIDNode {
  static var children: [OIDNode.Type] { get }
}

internal protocol OIDLeaf: OIDNode, OIDRef {
  static var all: [OIDLeaf] { get }
}

extension OIDLeaf where Self: RawRepresentable & CaseIterable, RawValue == OID {
  internal static var all: [OIDLeaf] { Array(Self.allCases) }
}
