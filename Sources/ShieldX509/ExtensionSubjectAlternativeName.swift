//
//  ExtensionSubjectAlternativeName.swift
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


public struct SubjectAltName: Equatable, Hashable, NonCriticalExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.subjectAltName.oid
  public static let asn1Schema = Schemas.SubjectAltName

  public var names: GeneralNames

  public init(names: GeneralNames) {
    self.names = names
  }
}



// MARK: Schemas

public extension Schemas {

  static let SubjectAltName: Schema = GeneralNames

}



extension SubjectAltName: Codable {

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
