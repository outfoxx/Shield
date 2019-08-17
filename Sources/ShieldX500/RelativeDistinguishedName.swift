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

  static func RelativeDistinguishedName(_ valueSet: Schema.DynamicMap, unknownTypeSchema: Schema) -> Schema {
    .setOf(AttributeTypeAndValue(valueSet, unknownTypeSchema: unknownTypeSchema), size: .min(1))
  }

  static func RDNSequence(_ valueSet: Schema.DynamicMap, unknownTypeSchema: Schema) -> Schema {
    .sequenceOf(RelativeDistinguishedName(valueSet, unknownTypeSchema: unknownTypeSchema))
  }

}
