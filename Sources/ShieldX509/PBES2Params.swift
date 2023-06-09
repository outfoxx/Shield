//
//  PBES.swift
//  
//
//  Created by Kevin Wooten on 6/8/23.
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

  private typealias rsadisDigAlg = iso.memberBody.us.rsadsi.digestAlgorithm
  private typealias rsadisEncAlg = iso.memberBody.us.rsadsi.encryptionAlgorithm
  private typealias nistAlgs = iso_itu.country.us.organization.gov.csor.nistAlgorithms.aes

  static let PBES2ParamsKeyDerivationFuncAlgorithms: Schema.DynamicMap = [
    iso.memberBody.us.rsadsi.pkcs.pkcs5.pbkdf2.asn1: PBKDF2Params
  ]

  static let PBES2ParamsEncryptionSchemeAlgorithms: Schema.DynamicMap = [
    rsadisEncAlg.rc2CBC.asn1: .null,
    rsadisEncAlg.rc2ECB.asn1: .null,
    rsadisEncAlg.rc4.asn1: .null,
    rsadisEncAlg.rc4WithMAC.asn1: .null,
    rsadisEncAlg.desxCBC.asn1: .null,
    rsadisEncAlg.desEDE3CBC.asn1: .null,
    rsadisEncAlg.rc5CBC.asn1: .null,
    rsadisEncAlg.rc5CBCPad.asn1: .null,
    rsadisEncAlg.desCDMF.asn1: .null,
    rsadisEncAlg.desEDE3.asn1: .null,

    nistAlgs.aes128_ECB.asn1: .null,
    nistAlgs.aes128_CBC_PAD.asn1: .null,
    nistAlgs.aes128_OFB.asn1: .null,
    nistAlgs.aes128_CFB.asn1: .null,
    nistAlgs.aes128_wrap.asn1: .null,
    nistAlgs.aes128_GCM.asn1: .null,
    nistAlgs.aes128_CCM.asn1: .null,
    nistAlgs.aes128_wrap_pad.asn1: .null,
    nistAlgs.aes128_GMAC.asn1: .null,

    nistAlgs.aes192_ECB.asn1: .null,
    nistAlgs.aes192_CBC_PAD.asn1: .null,
    nistAlgs.aes192_OFB.asn1: .null,
    nistAlgs.aes192_CFB.asn1: .null,
    nistAlgs.aes192_wrap.asn1: .null,
    nistAlgs.aes192_GCM.asn1: .null,
    nistAlgs.aes192_CCM.asn1: .null,
    nistAlgs.aes192_wrap_pad.asn1: .null,
    nistAlgs.aes192_GMAC.asn1: .null,

    nistAlgs.aes256_ECB.asn1: .null,
    nistAlgs.aes256_CBC_PAD.asn1: .null,
    nistAlgs.aes256_OFB.asn1: .null,
    nistAlgs.aes256_CFB.asn1: .null,
    nistAlgs.aes256_wrap.asn1: .null,
    nistAlgs.aes256_GCM.asn1: .null,
    nistAlgs.aes256_CCM.asn1: .null,
    nistAlgs.aes256_wrap_pad.asn1: .null,
    nistAlgs.aes256_GMAC.asn1: .null,
  ]

  static let PBES2Params: Schema =
    .sequence([
      "keyDerivationFunc": algorithmIdentifier(PBES2ParamsKeyDerivationFuncAlgorithms),
      "encryptionScheme": algorithmIdentifier(PBES2ParamsEncryptionSchemeAlgorithms)
    ])

}
