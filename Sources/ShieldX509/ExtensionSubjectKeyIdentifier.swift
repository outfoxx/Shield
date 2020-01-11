//
//  ExtensionSubjectKeyIdentifier.swift
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


public struct SubjectKeyIdentifier: Equatable, Hashable, NonCriticalExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.subjectKeyIdentifier.oid
  public static let asn1Schema = Schemas.SubjectKeyIdentifier

  public var value: KeyIdentifier

  public init(value: KeyIdentifier) {
    self.value = value
  }
}

extension SubjectKeyIdentifier: Codable {

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    value = try container.decode(KeyIdentifier.self)
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.singleValueContainer()
    try container.encode(value)
  }

}


// MARK: Schemas

public extension Schemas {

  static let SubjectKeyIdentifier: Schema = KeyIdentifier

}
