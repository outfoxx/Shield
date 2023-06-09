//
//  EncryptedPrivateKeyInfo.swift
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

public struct EncryptedPrivateKeyInfo: Equatable, Hashable, Codable {

  public var encryptionAlgorithm: AlgorithmIdentifier
  public var encryptedData: Data

  public init(encryptionAlgorithm: AlgorithmIdentifier, encryptedData: Data) {
    self.encryptionAlgorithm = encryptionAlgorithm
    self.encryptedData = encryptedData
  }

}

extension EncryptedPrivateKeyInfo: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.EncryptedPrivateKeyInfo }

}

public extension Schemas {

  static let EncryptedPrivateKeyInfoAlgorithms: Schema.DynamicMap = [
    iso.memberBody.us.rsadsi.pkcs.pkcs1.rsaEncryption.asn1: .null,
    iso.memberBody.us.ansix962.keyType.ecPublicKey.asn1: ECParameters,
  ]

  static let EncryptedPrivateKeyInfo: Schema =
    .sequence([
      "encryptionAlgorithm": algorithmIdentifier(EncryptedPrivateKeyInfoAlgorithms),
      "encryptedData": .octetString(),
    ])

}
