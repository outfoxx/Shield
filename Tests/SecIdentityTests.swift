//
//  SecIdentityTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


class SecIdentityTests: XCTestCase {

  func testBuildAndFetch() throws {

    let keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [])
    defer { try? keyPair.delete() }

    let subject: Name = try NameBuilder()
      .add("Test Guy", forTypeName: "CN")
      .add("Test Corp", forTypeName: "O")
      .add("TC", forTypeName: "C")
      .name

    // Build a self-signed certificate for importing
    let cert =
      try Certificate.Builder()
        .subject(name: subject)
        .issuer(name: subject)
        .publicKey(keyPair: keyPair, usage: [.nonRepudiation])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .sec()!
    defer {
      SecItemDelete([
        kSecClass as String: kSecClassCertificate,
        kSecMatchItemList as String: [cert] as CFArray,
        kSecMatchLimit as String: kSecMatchLimitOne,
      ] as [String: Any] as CFDictionary)
    }

    // Ensure all went well
    let ident: SecIdentity
    do {
      ident = try SecIdentity.create(certificate: cert, keyPair: keyPair)
    }
    catch SecIdentity.Error.saveFailed {
      #if os(macOS)
      throw XCTSkip("Missing keychain entitlement")
      #else
      return XCTFail("Save failed")
      #endif
    }
    defer {
      try? cert.delete()
      try? keyPair.delete()
    }

    XCTAssertNotNil(ident)
    XCTAssertNotNil(try ident.certificate())
    XCTAssertNotNil(try ident.privateKey())
  }

}
