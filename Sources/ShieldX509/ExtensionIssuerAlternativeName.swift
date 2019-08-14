//
//  File.swift
//  
//
//  Created by Kevin Wooten on 8/13/19.
//

import Foundation
import PotentASN1
import ShieldOID


public struct IssuerAltName: Equatable, Hashable, ExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.issuerAltName.oid
  public static let asn1Schema = Schemas.IssuerAltName
  public var isCritical: Bool { false }

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
