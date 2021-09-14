//
//  RelativeDistinguishedName.swift
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


public typealias RDNSequence<Mapper: AttributeValueMapper> = [RelativeDistinguishedName<Mapper>]
public typealias RelativeDistinguishedName<Mapper: AttributeValueMapper> = [AttributeTypeAndValue<Mapper>]


public extension Schemas {

  @available(*, deprecated, message: "Use relativeDistinguishedName(Schema.DynamicMap, unknownTypeSchema: Schema) instead")
  // swiftlint:disable:next identifier_name
  static func RelativeDistinguishedName(_ valueSet: Schema.DynamicMap, unknownTypeSchema: Schema) -> Schema {
    return relativeDistinguishedName(valueSet, unknownTypeSchema: unknownTypeSchema)
  }

  static func relativeDistinguishedName(_ valueSet: Schema.DynamicMap, unknownTypeSchema: Schema) -> Schema {
    .setOf(attributeTypeAndValue(valueSet, unknownTypeSchema: unknownTypeSchema), size: .min(1))
  }

  @available(*, deprecated, message: "Use rdnSequence(Schema.DynamicMap, unknownTypeSchema: Schema) instead")
  static func RDNSequence(_ valueSet: Schema.DynamicMap, unknownTypeSchema: Schema) -> Schema {
    return rdnSequence(valueSet, unknownTypeSchema: unknownTypeSchema)
  }

  static func rdnSequence(_ valueSet: Schema.DynamicMap, unknownTypeSchema: Schema) -> Schema {
    .sequenceOf(relativeDistinguishedName(valueSet, unknownTypeSchema: unknownTypeSchema))
  }

}
