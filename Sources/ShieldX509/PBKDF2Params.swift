//
//  PBKDF2Params.swift
//  
//
//  Created by Kevin Wooten on 6/8/23.
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

  private typealias digAlgs = iso.memberBody.us.rsadsi.digestAlgorithm

  private static let PRFAglorithms: Schema.DynamicMap = [
    digAlgs.hmacWithSHA1.asn1: .null,
    digAlgs.hmacWithSHA224.asn1: .null,
    digAlgs.hmacWithSHA256.asn1: .null,
    digAlgs.hmacWithSHA384.asn1: .null,
    digAlgs.hmacWithSHA512.asn1: .null,
  ]

  static let PBKDF2Params: Schema =
    .sequence([
      "salt": .choiceOf([.octetString(), .objectIdentifier()]),
      "iterationCount": .integer(),
      "keyLength": .optional(.integer()),
      "prf": algorithmIdentifier(PRFAglorithms)
    ])

}
