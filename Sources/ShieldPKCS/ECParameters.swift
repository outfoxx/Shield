//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/23/19.
//

import Foundation
import PotentASN1


public typealias ECParameters = ObjectIdentifier



// MARK: Schemas

public extension Schemas {

  static let ECParameters: Schema =
    .choiceOf([
      .objectIdentifier(),  // -- named curve
      // .null              // -- implicit curve
      // SpecifiedECDomain, // -- specified curve
    ])

}
