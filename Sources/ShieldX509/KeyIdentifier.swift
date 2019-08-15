//
//  KeyIdentifier.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public typealias KeyIdentifier = Data



// MARK: Schemas

public extension Schemas {

  static let KeyIdentifier: Schema = .octetString()

}
