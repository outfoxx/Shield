//
//  CertificationRequestInfo.swift
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


public struct CertificationRequestInfo: Equatable, Hashable, Codable {

  public enum Version: Int, CaseIterable, Equatable, Hashable, Codable {
    case v1 = 0
  }

  public var version: Version
  public var subject: Name
  public var subjectPKInfo: SubjectPublicKeyInfo
  public var attributes: CRAttributes?

  public init(version: Version, subject: Name, subjectPKInfo: SubjectPublicKeyInfo, attributes: CRAttributes?) {
    self.version = version
    self.subject = subject
    self.subjectPKInfo = subjectPKInfo
    self.attributes = attributes
  }

}


extension CertificationRequestInfo: SchemaSpecified {

  public static var asn1Schema: Schema { Schemas.CertificationRequestInfo }

}



// MARK: Schemas

public extension Schemas {

  static let CRIAttributes: Schema.DynamicMap = [
    iso.memberBody.us.rsadsi.pkcs.pkcs9.extensionRequest.asn1: Extensions,
    iso.memberBody.us.rsadsi.pkcs.pkcs9.extendedCertificateAttributes.asn1: attributes([:], unknownTypeSchema: .any),
  ]

  static let CertificationRequestInfo: Schema =
    .sequence([
      "version": .version(.integer(allowed: 0 ..< 1)),
      "subject": Name,
      "subjectPKInfo": SubjectPublicKeyInfo,
      "attributes": .optional(.implicit(0, attributes(CRIAttributes))),
    ])

}
