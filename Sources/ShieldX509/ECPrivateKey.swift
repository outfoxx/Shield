//
//  ECPrivateKey.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct ECPrivateKey: Equatable, Hashable, Codable {

  public enum Version: Int, CaseIterable, Equatable, Hashable, Codable {
    case one = 1
  }

  public var version: Version
  public var privateKey: Data
  public var parameters: ECParameters?
  public var publicKey: BitString?

  public init(version: Version = .one, privateKey: Data, parameters: ECParameters? = nil, publicKey: BitString? = nil) {
    self.version = version
    self.privateKey = privateKey
    self.parameters = parameters
    self.publicKey = publicKey
  }

}

extension ECPrivateKey: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.ECPrivateKey }

}

public extension Schemas {

  static let ECPrivateKey: Schema =
    .sequence([
      "version": .version(.integer(allowed: 1 ..< 2)),
      "privateKey": .octetString(),
      "parameters": .optional(.explicit(0, ECParameters)),
      "publicKey": .optional(.explicit(1, .bitString())),
    ])

}
