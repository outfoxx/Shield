//
//  ExtensionAuthorityKeyIdentifier.swift
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


public struct AuthorityKeyIdentifier: Equatable, Hashable, Codable, ExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.authorityKeyIdentifier.oid
  public static let asn1Schema: Schema = Schemas.AuthorityKeyIdentifier
  public var isCritical: Bool { false }

  public var keyIdentifier: KeyIdentifier?
  public var authorityCertIssuer: GeneralNames?
  public var authorityCertSerialNumber: TBSCertificate.SerialNumber?

  public init(keyIdentifier: KeyIdentifier? = nil,
              authorityCertIssuer: GeneralNames? = nil,
              authorityCertSerialNumber: TBSCertificate.SerialNumber? = nil) {
    self.keyIdentifier = keyIdentifier
    self.authorityCertIssuer = authorityCertIssuer
    self.authorityCertSerialNumber = authorityCertSerialNumber
  }
}



// MARK: Schemas

public extension Schemas {

  static let AuthorityKeyIdentifier: Schema =
    .sequence([
      "keyIdentifier": .optional(.implicit(0, KeyIdentifier)),
      "authorityCertIssuer": .optional(.implicit(1, GeneralNames)),
      "authorityCertSerialNumber": .optional(.implicit(2, CertificateSerialNumber)),
    ])

}
