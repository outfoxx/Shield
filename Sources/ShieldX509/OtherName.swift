//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1


public struct OtherName: Equatable, Hashable, Codable {
  public var typeId: ObjectIdentifier
  public var value: ASN1
}



// MARK: Schemas

public extension Schemas {

  static let OtherName: Schema =
    .sequence([
      "typeId": .type(.objectIdentifier()),
      "value": .explicit(0, in: .contextSpecific, .dynamic([:]))
    ])

}
