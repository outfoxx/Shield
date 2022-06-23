//
//  EDIPartyName.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldX500


public struct EDIPartyName: Equatable, Hashable, Codable {
  public var nameAssigner: AnyString?
  public var partyName: AnyString

  public init(nameAssigner: AnyString? = nil, partyName: AnyString) {
    self.nameAssigner = nameAssigner
    self.partyName = partyName
  }
}



// MARK: Schemas

public extension Schemas {

  static let EDIPartyName: Schema =
    .sequence([
      "nameAssigner": .explicit(0, .optional(directoryString())),
      "partyName": .explicit(1, directoryString()),
    ])

}
