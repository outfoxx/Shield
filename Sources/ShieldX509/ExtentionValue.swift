//
//  ExtentionValue.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public protocol ExtensionValue: Codable, SchemaSpecified {
  static var extensionID: ObjectIdentifier { get }
}


public protocol CriticalExtensionValue: ExtensionValue {}
public protocol NonCriticalExtensionValue: ExtensionValue {}
