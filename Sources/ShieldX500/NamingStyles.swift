//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/24/19.
//

import Foundation
import ShieldOID


public struct NamingStyle: NamingStyleProtocol, CustomStringConvertible {

  private var implementation: NamingStyleProtocol

  public init(implementation: NamingStyleProtocol) {
    self.implementation = implementation
  }

  public func oid(fromName: String) -> OID? {
    return implementation.oid(fromName: fromName)
  }

  public func name(fromOID: OID) -> String? {
    return implementation.name(fromOID: fromOID)
  }

  public var description: String { String(describing: implementation) }

}

public protocol NamingStyleProtocol: CustomStringConvertible {

  func oid(fromName: String) -> OID?
  func name(fromOID: OID) -> String?

  static func decode(attributeName: String, mapping: [String: OID]) -> OID?

}

public extension NamingStyleProtocol {

  static func decode(attributeName name: String, mapping: [String:OID]) -> OID? {

    let start = name.startIndex, end = name.endIndex

    if let firstFour = name.index(start, offsetBy: 4, limitedBy: end), name[...firstFour].uppercased() == "OID." {
      return OID(String(name[firstFour...]))
    }
    else if start != end, name[start].isASCII && name[start].isNumber {
      return OID(name)
    }

    return mapping[name.lowercased()]
  }

}


// MARK:  RFC4519 Style

public extension NamingStyle {
  static var rfc4519: NamingStyle { RFC4519Style.instance }
}

public struct RFC4519Style: NamingStyleProtocol {

  public static let instance = NamingStyle(implementation: Self())

  static let typeNameTable: [String: OID] = [
    "businessCategory": "2.5.4.15",
    "c": "2.5.4.6",
    "cn": "2.5.4.3",
    "dc": "0.9.2342.19200300.100.1.25",
    "description": "2.5.4.13",
    "destinationIndicator": "2.5.4.27",
    "distinguishedName": "2.5.4.49",
    "dnQualifier": "2.5.4.46",
    "enhancedSearchGuide": "2.5.4.47",
    "facsimileTelephoneNumber": "2.5.4.23",
    "generationQualifier": "2.5.4.44",
    "givenName": "2.5.4.42",
    "houseIdentifier": "2.5.4.51",
    "initials": "2.5.4.43",
    "internationalISDNNumber": "2.5.4.25",
    "l": "2.5.4.7",
    "member": "2.5.4.31",
    "name": "2.5.4.41",
    "o": "2.5.4.10",
    "ou": "2.5.4.11",
    "owner": "2.5.4.32",
    "physicalDeliveryOfficeName": "2.5.4.19",
    "postalAddress": "2.5.4.16",
    "postalCode": "2.5.4.17",
    "postOfficeBox": "2.5.4.18",
    "preferredDeliveryMethod": "2.5.4.28",
    "registeredAddress": "2.5.4.26",
    "roleOccupant": "2.5.4.33",
    "searchGuide": "2.5.4.14",
    "seeAlso": "2.5.4.34",
    "serialNumber": "2.5.4.5",
    "sn": "2.5.4.4",
    "st": "2.5.4.8",
    "street": "2.5.4.9",
    "telephoneNumber": "2.5.4.20",
    "teletexTerminalIdentifier": "2.5.4.22",
    "telexNumber": "2.5.4.21",
    "title": "2.5.4.12",
    "uid": "0.9.2342.19200300.100.1.1",
    "uniqueMember": "2.5.4.50",
    "userPassword": "2.5.4.35",
    "x121Address": "2.5.4.24",
    "x500UniqueIdentifier": "2.5.4.45",
  ]

  static let byName: [String:OID] = {
    Dictionary(uniqueKeysWithValues: Self.typeNameTable.map { key, value in (key.lowercased(), value) })
  }()

  static let byOID: [OID:String] = {
    Dictionary(uniqueKeysWithValues: Self.typeNameTable.map { key, value in (value, key) })
  }()

  public var description: String { return "RFC4519" }

  public func name(fromOID oid: OID) -> String? {
    guard let name = Self.byOID[oid] else {
      return OID.dotOid(of: oid)
    }
    return name
  }

  public func oid(fromName name: String) -> OID? {
    return Self.decode(attributeName: name, mapping: Self.byName)
  }

  private init() {}

}
