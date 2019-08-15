//
//  ExtensionKeyUsage.swift
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


public struct KeyUsage: OptionSet, ExtensionValue, Equatable, Hashable, Codable {

  public static var extensionID = iso_itu.ds.certificateExtension.keyUsage.oid
  public static var asn1Schema = Schemas.keyUsageExtension
  public var isCritical: Bool { true }

  public let rawValue: UInt16

  public init(rawValue: UInt16) {
    self.rawValue = rawValue
  }

  public static let digitalSignature = KeyUsage(rawValue: 1 << 0)
  public static let nonRepudiation = KeyUsage(rawValue: 1 << 1)
  public static let keyEncipherment = KeyUsage(rawValue: 1 << 2)
  public static let dataEncipherment = KeyUsage(rawValue: 1 << 3)
  public static let keyAgreement = KeyUsage(rawValue: 1 << 4)
  public static let keyCertSign = KeyUsage(rawValue: 1 << 5)
  public static let cRLSign = KeyUsage(rawValue: 1 << 6)
  public static let encipherOnly = KeyUsage(rawValue: 1 << 7)
  public static let decipherOnly = KeyUsage(rawValue: 1 << 8)

  public static let contentCommitment = nonRepudiation
}



// MARK: Schemas

public extension Schemas {

  static let keyUsageExtension: Schema = .bitString()

}


// MARK: KeyUsage Conformances

extension KeyUsage {

  public init(from decoder: Decoder) throws {
    let bitString = try decoder.singleValueContainer().decode(BitString.self)
    self = Self(rawValue: bitString.integer(UInt16.self))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(BitString(bitPattern: rawValue))
  }

}
