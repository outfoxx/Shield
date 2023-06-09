//
//  ECParameters.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public typealias ECParameters = ObjectIdentifier



// MARK: Schemas

public extension Schemas {

  static let ECParameters: Schema =
    .choiceOf([
      .objectIdentifier(), // -- named curve
      // .null              // -- implicit curve
      // SpecifiedECDomain, // -- specified curve
    ])

}
