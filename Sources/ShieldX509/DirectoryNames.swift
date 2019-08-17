//
//  DirectoryNames.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldOID
import ShieldX500


public typealias DirectoryName = RDNSequence<DirectoryNameAttributeMapper>


public struct DirectoryNameAttributeMapper: AttributeValueMapper {

  public static func encoder(forType type: ObjectIdentifier) -> ValueEncoder? {
    guard let schema = Schemas.DirectoryNames[.objectIdentifier(type.fields)] else { return nil }
    return { value in
      guard let string = value as? AnyString else {
        fatalError("AnyString required")
      }
      return try ASN1Encoder(schema: schema).encode(string)
    }
  }

  public static func decoder(forType type: ObjectIdentifier) -> ValueDecoder? {
    guard let schema = Schemas.DirectoryNames[.objectIdentifier(type.fields)] else { return nil }
    return { data in try ASN1Decoder(schema: schema).decode(AnyString.self, from: data) }
  }

  public static func handler(forType type: ObjectIdentifier) -> ShieldX500.AttributeValueHandler? {
    return ShieldX500.AnyStringAttributeValueHandler.instance
  }

}



// MARK: Schemas

public extension Schemas {

  static let DirectoryNames: Schema.DynamicMap = [
    iso_itu.ds.attributeType.name.asn1: X520Name,
    iso_itu.ds.attributeType.surname.asn1: X520Name,
    iso_itu.ds.attributeType.givenName.asn1: X520Name,
    iso_itu.ds.attributeType.initials.asn1: X520Name,
    iso_itu.ds.attributeType.generationQualifier.asn1: X520Name,
    iso_itu.ds.attributeType.commonName.asn1: X520CommonName,
    iso_itu.ds.attributeType.localityName.asn1: X520LocalityName,
    iso_itu.ds.attributeType.stateOrProvinceName.asn1: X520StateOrProvinceName,
    iso_itu.ds.attributeType.organizationName.asn1: X520OrganizationName,
    iso_itu.ds.attributeType.organizationalUnitName.asn1: X520OrganizationalUnitName,
    iso_itu.ds.attributeType.title.asn1: X520Title,
    iso_itu.ds.attributeType.dnQualifier.asn1: .string(kind: .printable),
    iso_itu.ds.attributeType.countryName.asn1: .string(kind: .printable, size: .is(2)),
    iso_itu.ds.attributeType.serialNumber.asn1: .string(kind: .printable, size: .range(1, 64)),
    iso_itu.ds.attributeType.pseudonym.asn1: X520Pseudonym,
    itu.data.pss.ucl.pilot.pilotAttributeType.domainComponent.asn1: .string(kind: .ia5),
    iso.memberBody.us.rsadsi.pkcs.pkcs9.emailAddres.asn1: .string(kind: .ia5, size: .range(1, 255)),
  ]

  static let X520Name = DirectoryString(max: 32768)
  static let X520CommonName = DirectoryString(max: 64)
  static let X520LocalityName = DirectoryString(max: 128)
  static let X520StateOrProvinceName = DirectoryString(max: 128)
  static let X520OrganizationName = DirectoryString(max: 64)
  static let X520OrganizationalUnitName = DirectoryString(max: 64)
  static let X520Title = DirectoryString(max: 64)
  static let X520Pseudonym = DirectoryString(max: 128)

  static func DirectoryString(max: Int = .max) -> Schema {
    .choiceOf([
      .string(kind: .utf8, size: .range(1, max)),
      .string(kind: .printable, size: .range(1, max)),
      .string(kind: .teletex, size: .range(1, max)),
      .string(kind: .visible, size: .range(1, max)),
      .string(kind: .bmp, size: .range(1, max)),
    ])
  }

}
