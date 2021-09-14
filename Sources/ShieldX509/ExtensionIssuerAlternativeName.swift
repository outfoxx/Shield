//
//  ExtensionIssuerAlternativeName.swift
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


public struct IssuerAltName: Equatable, Hashable, NonCriticalExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.issuerAltName.oid
  public static let asn1Schema = Schemas.IssuerAltName

  public var names: GeneralNames

  public init(names: GeneralNames) {
    self.names = names
  }
}



// MARK: Schemas

public extension Schemas {

  static let IssuerAltName: Schema = GeneralNames

}



extension IssuerAltName: Codable {

  public init(from decoder: Decoder) throws {
    var container = try decoder.unkeyedContainer()
    var names = GeneralNames()
    for _ in 0 ..< (container.count ?? 0) {
      names.append(try container.decode(GeneralName.self))
    }
    self.names = names
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.unkeyedContainer()
    for name in names {
      try container.encode(name)
    }
  }

}
