//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1
import ShieldOID


public struct AuthorityKeyIdentifier: Equatable, Hashable, Codable, ExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.authorityKeyIdentifier.oid
  public static let asn1Schema: Schema = Schemas.AuthorityKeyIdentifier
  public var isCritical: Bool { false }

  public var keyIdentifier: KeyIdentifier
  public var authorityCertIssuer: GeneralName
  public var authorityCertSerialNumber: TBSCertificate.SerialNumber

  public init(keyIdentifier: KeyIdentifier,
              authorityCertIssuer: GeneralName,
              authorityCertSerialNumber: TBSCertificate.SerialNumber) {
    self.keyIdentifier = keyIdentifier
    self.authorityCertIssuer = authorityCertIssuer
    self.authorityCertSerialNumber = authorityCertSerialNumber
  }
}



// MARK: Schemas

public extension Schemas {

  static let AuthorityKeyIdentifier: Schema =
    .sequence([
      "keyIdentifier":                .implicit(0, .optional(KeyIdentifier)),
      "authorityCertIssuer":          .implicit(1, .optional(GeneralName)),
      "authorityCertSerialNumber":    .implicit(2, .optional(CertificateSerialNumber))
    ])

}
