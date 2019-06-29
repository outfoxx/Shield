//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1


public struct SubjectPublicKeyInfo: Equatable, Hashable, Codable {

  public var algorithm: AlgorithmIdentifier
  public var subjectPublicKey: Data

  public init(algorithm: AlgorithmIdentifier, subjectPublicKey: Data) {
    self.algorithm = algorithm
    self.subjectPublicKey = subjectPublicKey
  }

}



// MARK: Schemas

public extension Schemas {

  static func SubjectPublicKeyInfo(_ ioSet: Schema.DynamicMap) -> Schema {
    .sequence([
      "algorithm": AlgorithmIdentifier(ioSet),
      "subjectPublicKey": .bitString()
    ])
  }

}
