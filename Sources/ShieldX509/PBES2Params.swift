//
//  PBES.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import BigInt
import Foundation
import PotentASN1
import ShieldOID

public struct PBES2Params: Equatable, Hashable, Codable {

  public var keyDerivationFunc: AlgorithmIdentifier
  public var encryptionScheme: AlgorithmIdentifier

  public init(keyDerivationFunc: AlgorithmIdentifier, encryptionScheme: AlgorithmIdentifier) {
    self.keyDerivationFunc = keyDerivationFunc
    self.encryptionScheme = encryptionScheme
  }
}

extension PBES2Params: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.PBES2Params }

}

public extension Schemas {

  private typealias RSADSIDigAlgs = iso.memberBody.us.rsadsi.digestAlgorithm
  private typealias RSADSIEncAlgs = iso.memberBody.us.rsadsi.encryptionAlgorithm
  private typealias NISTAlgs = iso_itu.country.us.organization.gov.csor.nistAlgorithms.aes

  static let PBES2ParamsKeyDerivationFuncAlgorithms: Schema.DynamicMap = [
    iso.memberBody.us.rsadsi.pkcs.pkcs5.pbkdf2.asn1: PBKDF2Params
  ]

  static let PBES2ParamsEncryptionSchemeAlgorithms: Schema.DynamicMap = [
    RSADSIEncAlgs.rc2CBC.asn1: .null,
    RSADSIEncAlgs.rc2ECB.asn1: .null,
    RSADSIEncAlgs.rc4.asn1: .null,
    RSADSIEncAlgs.rc4WithMAC.asn1: .null,
    RSADSIEncAlgs.desxCBC.asn1: .null,
    RSADSIEncAlgs.desEDE3CBC.asn1: .null,
    RSADSIEncAlgs.rc5CBC.asn1: .null,
    RSADSIEncAlgs.rc5CBCPad.asn1: .null,
    RSADSIEncAlgs.desCDMF.asn1: .null,
    RSADSIEncAlgs.desEDE3.asn1: .null,

    NISTAlgs.aes128_ECB.asn1: .null,
    NISTAlgs.aes128_CBC_PAD.asn1: .null,
    NISTAlgs.aes128_OFB.asn1: .null,
    NISTAlgs.aes128_CFB.asn1: .null,
    NISTAlgs.aes128_wrap.asn1: .null,
    NISTAlgs.aes128_GCM.asn1: .null,
    NISTAlgs.aes128_CCM.asn1: .null,
    NISTAlgs.aes128_wrap_pad.asn1: .null,
    NISTAlgs.aes128_GMAC.asn1: .null,

    NISTAlgs.aes192_ECB.asn1: .null,
    NISTAlgs.aes192_CBC_PAD.asn1: .null,
    NISTAlgs.aes192_OFB.asn1: .null,
    NISTAlgs.aes192_CFB.asn1: .null,
    NISTAlgs.aes192_wrap.asn1: .null,
    NISTAlgs.aes192_GCM.asn1: .null,
    NISTAlgs.aes192_CCM.asn1: .null,
    NISTAlgs.aes192_wrap_pad.asn1: .null,
    NISTAlgs.aes192_GMAC.asn1: .null,

    NISTAlgs.aes256_ECB.asn1: .null,
    NISTAlgs.aes256_CBC_PAD.asn1: .null,
    NISTAlgs.aes256_OFB.asn1: .null,
    NISTAlgs.aes256_CFB.asn1: .null,
    NISTAlgs.aes256_wrap.asn1: .null,
    NISTAlgs.aes256_GCM.asn1: .null,
    NISTAlgs.aes256_CCM.asn1: .null,
    NISTAlgs.aes256_wrap_pad.asn1: .null,
    NISTAlgs.aes256_GMAC.asn1: .null,
  ]

  static let PBES2Params: Schema =
    .sequence([
      "keyDerivationFunc": algorithmIdentifier(PBES2ParamsKeyDerivationFuncAlgorithms),
      "encryptionScheme": algorithmIdentifier(PBES2ParamsEncryptionSchemeAlgorithms),
    ])

}
