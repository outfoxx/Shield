//
//  SecKeyType.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation


public enum SecKeyType: UInt32, CaseIterable, Codable {

  /// RSA Key
  case rsa
  /// Elliptical Curve Key with curve of P-192, P-256, P-384 or P-521 (based on key size).
  case ec

  public init?(systemValue: CFString) {
    switch systemValue {
    case kSecAttrKeyTypeRSA:
      self = .rsa
    case kSecAttrKeyTypeECSECPrimeRandom:
      self = .ec
    default:
      return nil
    }
  }

  public var systemValue: CFString {
    switch self {
    case .rsa:
      return kSecAttrKeyTypeRSA
    case .ec:
      return kSecAttrKeyTypeECSECPrimeRandom
    }
  }
}
