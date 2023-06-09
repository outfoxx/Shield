//
//  PrivateKeyInfo.swift
//
//
//  Created by Kevin Wooten on 6/7/23.
//

import Foundation
import ShieldOID
import PotentASN1

public struct PrivateKeyInfo: Equatable, Hashable, Codable {

  public enum Version: Int, CaseIterable, Equatable, Hashable, Codable {
    case zero = 0
  }

  public var version: Version
  public var privateKeyAlgorithm: AlgorithmIdentifier
  public var privateKey: Data

  public init(version: Version = .zero, privateKeyAlgorithm: AlgorithmIdentifier, privateKey: Data) {
    self.version = version
    self.privateKeyAlgorithm = privateKeyAlgorithm
    self.privateKey = privateKey
  }

}

extension PrivateKeyInfo: SchemaSpecified {
  public static var asn1Schema: Schema { Schemas.PrivateKeyInfo }
}

public extension Schemas {

  static let PrivateKeyInfoAlgorithms: Schema.DynamicMap = [
    iso.memberBody.us.rsadsi.pkcs.pkcs1.rsaEncryption.asn1: .null,
    iso.memberBody.us.ansix962.keyType.ecPublicKey.asn1: ECParameters,
  ]

  static let PrivateKeyInfoVersion: Schema = .integer(allowed: 0 ..< 1)

  static let PrivateKeyInfo: Schema =
    .sequence([
      "version": .version(PrivateKeyInfoVersion),
      "privateKeyAlgorithm": algorithmIdentifier(PrivateKeyInfoAlgorithms),
      "privateKey": .octetString(),
    ])

}
