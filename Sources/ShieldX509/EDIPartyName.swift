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
  public var nameAssigner: DirectoryName?
  public var partyName: DirectoryName
}



// MARK: Schemas

public extension Schemas {

  static let EDIPartyName: Schema =
    .sequence([
      "nameAssigner": .implicit(0, .optional(DirectoryString())),
      "value": .implicit(1, DirectoryString()),
    ])

}
