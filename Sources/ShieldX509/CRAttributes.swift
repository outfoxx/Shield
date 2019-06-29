//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/23/19.
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
