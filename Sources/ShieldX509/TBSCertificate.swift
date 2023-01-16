//
//  TBSCertificate.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldOID
import ShieldPKCS
import ShieldX500


public struct TBSCertificate: Equatable, Hashable, Codable {

  public enum Version: UInt, CaseIterable, Equatable, Hashable, Codable {
    case v1 = 0
    case v2 = 1
    case v3 = 2
  }

  public typealias SerialNumber = ASN1.Integer

  public struct Validity: Equatable, Hashable, Codable {

    public var notBefore: AnyTime
    public var notAfter: AnyTime

    public init(notBefore: AnyTime, notAfter: AnyTime) {
      self.notBefore = notBefore
      self.notAfter = notAfter
    }

  }

  public typealias UniqueIdentifier = Data

  public var version: Version
  public var serialNumber: SerialNumber
  public var signature: AlgorithmIdentifier
  public var issuer: Name
  public var validity: Validity
  public var subject: Name
  public var subjectPublicKeyInfo: SubjectPublicKeyInfo
  public var issuerUniqueID: UniqueIdentifier?
  public var subjectUniqueID: UniqueIdentifier?
  public var extensions: Extensions?

  public init(
    version: Version,
    serialNumber: ASN1.Integer,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subjectPublicKeyInfo: SubjectPublicKeyInfo,
    issuerUniqueID: UniqueIdentifier?,
    subjectUniqueID: UniqueIdentifier?,
    extensions: Extensions?
  ) {
    self.version = version
    self.serialNumber = serialNumber
    self.signature = signature
    self.issuer = issuer
    self.validity = validity
    self.subject = subject
    self.subjectPublicKeyInfo = subjectPublicKeyInfo
    self.issuerUniqueID = issuerUniqueID
    self.subjectUniqueID = subjectUniqueID
    self.extensions = extensions
  }

}


extension TBSCertificate: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.TBSCertificate }

}



// MARK: Schemas

public extension Schemas {

  static let PKInfoAlgorithms: Schema.DynamicMap = [
    iso.memberBody.us.rsadsi.pkcs.pkcs1.rsaEncryption.asn1: .null,
    iso.memberBody.us.ansix962.keyType.ecPublicKey.asn1: ShieldPKCS.Schemas.ECParameters,
  ]

  static let SignatureAlgorithms: Schema.DynamicMap = [
    iso.memberBody.us.rsadsi.pkcs.pkcs1.md2WithRSAEncryption.asn1: .optional(.null),
    iso.memberBody.us.rsadsi.pkcs.pkcs1.md4WithRSAEncryption.asn1: .optional(.null),
    iso.memberBody.us.rsadsi.pkcs.pkcs1.md5WithRSAEncryption.asn1: .optional(.null),
    iso.memberBody.us.rsadsi.pkcs.pkcs1.sha1WithRSASignature.asn1: .optional(.null),
    iso.memberBody.us.rsadsi.pkcs.pkcs1.sha224WithRSAEncryption.asn1: .optional(.null),
    iso.memberBody.us.rsadsi.pkcs.pkcs1.sha256WithRSAEncryption.asn1: .optional(.null),
    iso.memberBody.us.rsadsi.pkcs.pkcs1.sha384WithRSAEncryption.asn1: .optional(.null),
    iso.memberBody.us.rsadsi.pkcs.pkcs1.sha512WithRSAEncryption.asn1: .optional(.null),
    iso.memberBody.us.ansix962.signatures.ecdsaWithSHA1.asn1: .null,
    iso.memberBody.us.ansix962.signatures.ecdsaWithSHA2.ecdsaWithSHA224.asn1: .nothing,
    iso.memberBody.us.ansix962.signatures.ecdsaWithSHA2.ecdsaWithSHA256.asn1: .nothing,
    iso.memberBody.us.ansix962.signatures.ecdsaWithSHA2.ecdsaWithSHA384.asn1: .nothing,
    iso.memberBody.us.ansix962.signatures.ecdsaWithSHA2.ecdsaWithSHA512.asn1: .nothing,
  ]

  static let TBSCertificate: Schema =
    .sequence([
      "version": .version(.explicit(0, Version)),
      "serialNumber": CertificateSerialNumber,
      "signature": algorithmIdentifier(SignatureAlgorithms),
      "issuer": Name,
      "validity": Validity,
      "subject": Name,
      "subjectPublicKeyInfo": SubjectPublicKeyInfo,
      "issuerUniqueID": .versioned(range: 1 ... 2, .implicit(1, UniqueIdentifier)),
      "subjectUniqueID": .versioned(range: 1 ... 2, .implicit(2, UniqueIdentifier)),
      "extensions": .versioned(range: 2 ... 2, .explicit(3, Extensions)),
    ])

  static let Version: Schema = .integer(allowed: 0 ..< 3, default: 0)

  static let CertificateSerialNumber: Schema =
    .integer()

  static let Time: Schema =
    .choiceOf([
      .time(kind: .utc),
      .time(kind: .generalized),
    ])

  static let Validity: Schema =
    .sequence([
      "notBefore": Time,
      "notAfter": Time,
    ])

  static let UniqueIdentifier: Schema =
    .bitString()

}
