//
//  ExtensionExtKeyUsage.swift
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


public struct ExtKeyUsage: Equatable, Hashable, Codable, ExtensionValue {

  public static var extensionID = iso_itu.ds.certificateExtension.extKeyUsage.oid
  public static var asn1Schema = Schemas.extKeyUsageExtension

  public var keyPurposes: Set<OID>

  public init(keyPurposes: Set<OID>) {
    self.keyPurposes = keyPurposes
  }
}



// MARK: Schemas

public extension Schemas {

  static let extKeyUsageExtension: Schema = .sequenceOf(.objectIdentifier())

}


// MARK: KeyUsage Conformances

public extension ExtKeyUsage {

  init(from decoder: Decoder) throws {
    var container = try decoder.unkeyedContainer()
    var keyPurposes = Set<OID>()
    for _ in 0 ..< (container.count ?? 0) {
      keyPurposes.insert(try container.decode(OID.self))
    }
    self.keyPurposes = keyPurposes
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.unkeyedContainer()
    for keyPurpose in keyPurposes {
      try container.encode(keyPurpose)
    }
  }

}
