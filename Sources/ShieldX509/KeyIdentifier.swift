//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1


public typealias KeyIdentifier = OctetString



// MARK: Schemas

public extension Schemas {

  static let KeyIdentifier: Schema = .octetString()

}
