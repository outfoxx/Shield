//
//  AlgorithmIdentifier.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct AlgorithmIdentifier: Equatable, Hashable, Codable {

  public var algorithm: ObjectIdentifier
  public var parameters: ASN1?

  public init(algorithm: ObjectIdentifier, parameters: ASN1? = nil) {
    self.algorithm = algorithm
    self.parameters = parameters
  }

}



// MARK: Schemas

public extension Schemas {

  @available(*, deprecated, message: "Use algorithmIdentifier(Schema.DynamicMap) instead")
  // swiftlint:disable:next identifier_name
  static func AlgorithmIdentifier(_ ioSet: Schema.DynamicMap) -> Schema {
    return algorithmIdentifier(ioSet)
  }

  static func algorithmIdentifier(_ ioSet: Schema.DynamicMap) -> Schema {
    .sequence([
      "algorithm": .type(.objectIdentifier()),
      "parameters": .dynamic(ioSet),
    ])
  }

}
