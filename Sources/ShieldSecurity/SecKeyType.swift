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

  case rsa
  case ec
  case ecSECPrimeRandom

  public init?(systemValue: CFString) {
    switch systemValue {
    case kSecAttrKeyTypeRSA:
      self = .rsa
    case kSecAttrKeyTypeEC:
      self = .ec
    case kSecAttrKeyTypeECSECPrimeRandom:
      self = .ecSECPrimeRandom
    default:
      return nil
    }
  }

  public var systemValue: CFString {
    switch self {
    case .rsa:
      return kSecAttrKeyTypeRSA
    case .ec:
      return kSecAttrKeyTypeEC
    case .ecSECPrimeRandom:
      return kSecAttrKeyTypeECSECPrimeRandom
    }
  }
}
