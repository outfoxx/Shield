//
//  File.swift
//
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1
import ShieldOID


public struct BasicConstraints: Equatable, Hashable, Codable, ExtensionValue {

  public static let extensionID = iso_itu.ds.certificateExtension.basicConstraints.oid
  public static let asn1Schema = Schemas.BasicConstraints
  public var isCritical: Bool { true }

  public let ca: Bool
  public let pathLenConstraint: Int?

  public init(ca: Bool, pathLenConstraint: Int? = nil) {
    self.ca = ca
    self.pathLenConstraint = pathLenConstraint
  }
}



// MARK: Schemas

public extension Schemas {

  static let BasicConstraints: Schema =
    .sequence([
      "ca": .boolean(default: false),
      "pathLenConstraint": .integer(allowed: 0 ..< Int.max)
    ])

}
