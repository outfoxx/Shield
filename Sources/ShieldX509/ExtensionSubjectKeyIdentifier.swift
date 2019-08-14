//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1
import ShieldOID


public struct SubjectKeyIdentifier: Equatable, Hashable, ExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.subjectKeyIdentifier.oid
  public static let asn1Schema = Schemas.SubjectKeyIdentifier
  public var isCritical: Bool { false }

  public var value: KeyIdentifier

  public init(value: KeyIdentifier) {
    self.value = value
  }
}

extension SubjectKeyIdentifier: Codable {

  public init(from decoder: Decoder) throws {
    let container = try decoder.singleValueContainer()
    self.value = try container.decode(KeyIdentifier.self)
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
