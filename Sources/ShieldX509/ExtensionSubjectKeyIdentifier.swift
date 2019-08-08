//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1
import ShieldOID


public struct SubjectKeyIdentifier: Equatable, Hashable, Codable, ExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.subjectKeyIdentifier.oid
  public static let asn1Schema = Schemas.SubjectKeyIdentifier
  public var isCritical: Bool { false }

  public var value: KeyIdentifier

  public init(value: KeyIdentifier) {
    self.value = value
  }
}



// MARK: Schemas

public extension Schemas {

  static let SubjectKeyIdentifier: Schema = KeyIdentifier

}
