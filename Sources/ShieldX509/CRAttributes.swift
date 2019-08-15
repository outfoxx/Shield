//
//  CRAttributes.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct CRAttributeValuesHandler: AttributeValuesHandler {

  public static let supported: [ObjectIdentifier: AttributeValue.Type] = [
    Extensions.attributeType: Extensions.self,
  ]

  public static func handler(for attrType: ObjectIdentifier) -> AttributeValueHandler.Type {
    return supported[attrType]?.attributeHandler ?? UnknownAttributeValueHandler.self
  }

}


public typealias CRAttributes = Attributes<CRAttributeValuesHandler>
