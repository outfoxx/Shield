//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/16/19.
//

import Foundation
import PotentASN1


public protocol ExtensionValue: Codable, SchemaSpecified {
  static var extensionID: ObjectIdentifier { get }
  var isCritical: Bool { get }
}
