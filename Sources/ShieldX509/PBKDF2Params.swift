//
//  PBKDF2Params.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldOID

public struct PBKDF2Params: Equatable, Hashable, Codable {

  public var salt: Data
  public var iterationCount: UInt64
  public var keyLength: UInt64
  public var prf: AlgorithmIdentifier

  public init(salt: Data, iterationCount: UInt64, keyLength: UInt64, prf: AlgorithmIdentifier) {
    self.salt = salt
    self.iterationCount = iterationCount
    self.keyLength = keyLength
    self.prf = prf
  }

}

extension PBKDF2Params: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.PBKDF2Params }

}

public extension Schemas {

  private typealias DigAlgs = iso.memberBody.us.rsadsi.digestAlgorithm

  private static let PRFAglorithms: Schema.DynamicMap = [
    DigAlgs.hmacWithSHA1.asn1: .null,
    DigAlgs.hmacWithSHA224.asn1: .null,
    DigAlgs.hmacWithSHA256.asn1: .null,
    DigAlgs.hmacWithSHA384.asn1: .null,
    DigAlgs.hmacWithSHA512.asn1: .null,
  ]

  static let PBKDF2Params: Schema =
    .sequence([
      "salt": .choiceOf([.octetString(), .objectIdentifier()]),
      "iterationCount": .integer(),
      "keyLength": .optional(.integer()),
      "prf": algorithmIdentifier(PRFAglorithms),
    ])

}
