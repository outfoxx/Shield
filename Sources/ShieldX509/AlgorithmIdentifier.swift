//
//  AlgorithmIdentifier.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct AlgorithmIdentifier: Equatable, Hashable, Codable {

  public var algorithm: ObjectIdentifier
  public var parameters: ASN1

  public init(algorithm: ObjectIdentifier, parameters: ASN1 = .null) {
    self.algorithm = algorithm
    self.parameters = parameters
  }

}



// MARK: Schemas

public extension Schemas {

  static func AlgorithmIdentifier(_ ioSet: Schema.DynamicMap) -> Schema {
    .sequence([
      "algorithm": .type(.objectIdentifier()),
      "parameters": .dynamic(ioSet),
    ])
  }

}
