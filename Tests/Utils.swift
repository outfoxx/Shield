//
//  Utils.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Shield
import Security
import XCTest

func generateTestKeyPairChecked(
  type: SecKeyType,
  keySize: Int,
  flags: Set<SecKeyPair.Builder.Flag> = [.permanent],
  accessibility: SecAccessibility = .default
) throws -> SecKeyPair {
  let label: String = [
    "Test",
    flags.contains(.secureEnclave) ? "Secure Enclave" : nil,
    type == .ec ? "EC" : "RSA",
    "Key Pair",
  ].compactMap { $0 }.joined(separator: " ")

  do {
    return try SecKeyPair.Builder(type: type, keySize: keySize).generate(label: label,
                                                                         flags: flags,
                                                                         accessibility: accessibility)
  }
  catch let error where isEntitlementMissingError(error) {
    #if os(macOS)
    throw XCTSkip("Missing keychain entitlement")
    #else
    throw error
    #endif
  }
}

func isEntitlementMissingError(_ error: Error) -> Bool {
  let error = error as NSError
  return error.domain == NSOSStatusErrorDomain && error.code == -34018
}
