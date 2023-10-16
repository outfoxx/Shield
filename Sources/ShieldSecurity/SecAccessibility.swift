//
//  SecAccessibility.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Security


public enum SecAccessibility: Equatable {
  case `default`
  case unlocked(afterFirst: Bool, shared: Bool)
  case passcodeEnabled
#if ACCESSIBILITY_ALWAYS_ENABLED
  case always(shared: Bool)
#endif
}


extension SecAccessibility {

  var attr: Any {

    switch self {

#if ACCESSIBILITY_ALWAYS_ENABLED
    case .always(shared: true):
      return kSecAttrAccessibleAlways as String

    case .always(shared: false):
      return kSecAttrAccessibleAlwaysThisDeviceOnly as String
#endif

    case .unlocked(afterFirst: true, shared: true):
      return kSecAttrAccessibleAfterFirstUnlock as String

    case .unlocked(afterFirst: true, shared: false):
      return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String

    case .unlocked(afterFirst: false, shared: true), .default:
      return kSecAttrAccessibleWhenUnlocked as String

    case .unlocked(afterFirst: false, shared: false):
      return kSecAttrAccessibleWhenUnlockedThisDeviceOnly as String

    case .passcodeEnabled:
      return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String
    }
  }

}
