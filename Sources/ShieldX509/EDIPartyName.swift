//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
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
