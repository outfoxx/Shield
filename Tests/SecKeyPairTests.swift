//
//  SecKeyPairTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import CryptoKit
@testable import Shield
import XCTest


class SecKeyPairTests: XCTestCase {

  var rsaKeyPair: SecKeyPair!
  var ecKeyPair: SecKeyPair!

  override func setUpWithError() throws {
    try super.setUpWithError()

    rsaKeyPair = try SecKeyPair.Builder(type: .rsa, keySize: 2048).generate(label: "Test RSA Key")
    ecKeyPair = try SecKeyPair.Builder(type: .ec, keySize: 256).generate(label: "Test EC Key")
  }

  override func tearDownWithError() throws {

    try? rsaKeyPair?.delete()
    try? ecKeyPair?.delete()

    try super.tearDownWithError()
  }

  func testGeneratedRSA() throws {

    let privateKeyAttrs = [
      kSecAttrLabel: "Test RSA Key",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var privateKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(privateKeyAttrs, &privateKeyRef), errSecSuccess)
    XCTAssertNotNil(privateKeyRef)

    let publicKeyAttrs = [
      kSecAttrLabel: "Test RSA Key",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var publicKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(publicKeyAttrs as CFDictionary, &publicKeyRef), errSecSuccess)
    XCTAssertNotNil(publicKeyRef)
  }

  func testGeneratedEC() throws {

    let privateKeyAttrs = [
      kSecAttrLabel: "Test EC Key",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var privateKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(privateKeyAttrs, &privateKeyRef), errSecSuccess)
    XCTAssertNotNil(privateKeyRef)

    let publicKeyAttrs = [
      kSecAttrLabel: "Test EC Key",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var publicKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(publicKeyAttrs as CFDictionary, &publicKeyRef), errSecSuccess)
    XCTAssertNotNil(publicKeyRef)
  }

  func testInitECFromExternalPrivateKey() throws {

    let external = try ecKeyPair.privateKey.encode()

    XCTAssertNoThrow(try SecKeyPair(type: ecKeyPair.privateKey.keyType(), privateKeyData: external))
  }

  func testInitRSAFromExternalPrivateKey() throws {

    let external = try rsaKeyPair.privateKey.encode()

    XCTAssertNoThrow(try SecKeyPair(type: rsaKeyPair.privateKey.keyType(), privateKeyData: external))
  }

  func testPersistentLoadRSA() throws {

    let (privateKeyRef, publicKeyRef) = try rsaKeyPair.persistentReferences()

    XCTAssertNotNil(try SecKeyPair(privateKeyRef: privateKeyRef, publicKeyRef: publicKeyRef))
  }

  func testPersistentLoadEC() throws {

    let (privateKeyRef, publicKeyRef) = try ecKeyPair.persistentReferences()

    XCTAssertNotNil(try SecKeyPair(privateKeyRef: privateKeyRef, publicKeyRef: publicKeyRef))
  }

  func testCertificateMatching() throws {

    let name = try NameBuilder().add("Unit Testing", forTypeName: "CN").name

    let certData =
      try Certificate.Builder()
        .subject(name: name)
        .issuer(name: name)
        .publicKey(keyPair: rsaKeyPair, usage: [.keyEncipherment])
        .valid(for: 86400 * 5)
        .build(signingKey: rsaKeyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    let finishedX = expectation(description: "finished")

    DispatchQueue.global(qos: .userInitiated).async {
      defer { finishedX.fulfill() }

      let result = self.rsaKeyPair.matchesCertificate(certificate: cert, trustedCertificates: [cert])

      XCTAssertTrue(result)
    }

    waitForExpectations(timeout: 10.0)
  }

#if swift(>=5.5)
  func testCertificateMatchingAsync() async throws {

    let name = try NameBuilder().add("Unit Testing", forTypeName: "CN").name

    let certData =
      try Certificate.Builder()
        .subject(name: name)
        .issuer(name: name)
        .publicKey(keyPair: rsaKeyPair, usage: [.keyEncipherment])
        .valid(for: 86400 * 5)
        .build(signingKey: rsaKeyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    let result = await self.rsaKeyPair.matchesCertificate(certificate: cert, trustedCertificates: [cert])
    XCTAssertTrue(result)
  }
#endif

  func testImportExportEncryptedRSA() throws {

    let exportedKeyData = try rsaKeyPair.export(password: "123")

    let importedKeyPair = try SecKeyPair.import(fromData: exportedKeyData, withPassword: "123")

    XCTAssertThrowsError(try SecKeyPair.import(fromData: exportedKeyData, withPassword: "456"))

    let plainText = try Random.generate(count: 171)

    let cipherText1 = try rsaKeyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText2 = try importedKeyPair.privateKey.decrypt(cipherText: cipherText1, padding: .oaep)

    XCTAssertEqual(plainText, plainText2)

    let cipherText2 = try importedKeyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText3 = try rsaKeyPair.privateKey.decrypt(cipherText: cipherText2, padding: .oaep)

    XCTAssertEqual(plainText, plainText3)

    try rsaKeyPair.delete()
    defer { rsaKeyPair = nil }

    let cipherText3 = try importedKeyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText4 = try importedKeyPair.privateKey.decrypt(cipherText: cipherText3, padding: .oaep)

    XCTAssertEqual(plainText, plainText4)

  }

  func testImportExportRSA() throws {

    let exportedKeyData = try rsaKeyPair.export()

    let importedKeyPair = try SecKeyPair.import(fromData: exportedKeyData)

    let plainText = try Random.generate(count: 171)

    let cipherText1 = try rsaKeyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText2 = try importedKeyPair.privateKey.decrypt(cipherText: cipherText1, padding: .oaep)

    XCTAssertEqual(plainText, plainText2)
  }

  func testImportExportEncryptedEC() throws {

    let exportedKeyData = try ecKeyPair.export(password: "123")

    _ = try SecKeyPair.import(fromData: exportedKeyData, withPassword: "123")

    XCTAssertThrowsError(try SecKeyPair.import(fromData: exportedKeyData, withPassword: "456"))
  }

  func testImportExportEC192() throws {

    let ecKeyPair =
      try SecKeyPair.Builder(type: .ec, keySize: 192)
        .generate(label: "Test 192 EC Key")
    defer { try? ecKeyPair.delete() }

    XCTAssertThrowsError(try SecKeyPair.import(fromData: ecKeyPair.export())) { error in
      XCTAssertTrue(error is AlgorithmIdentifier.Error)
    }
  }

  func testImportExportEC256() throws {

    let ecKeyPair =
      try SecKeyPair.Builder(type: .ec, keySize: 256)
        .generate(label: "Test 256 EC Key")
    defer { try? ecKeyPair.delete() }

    _ = try SecKeyPair.import(fromData: ecKeyPair.export())
  }

  func testImportExportEC384() throws {

    let ecKeyPair =
      try SecKeyPair.Builder(type: .ec, keySize: 384)
        .generate(label: "Test 384 EC Key")
    defer { try? ecKeyPair.delete() }

    _ = try SecKeyPair.import(fromData: ecKeyPair.export())
  }

  func testImportExportEC521() throws {

    let ecKeyPair =
      try SecKeyPair.Builder(type: .ec, keySize: 521)
        .generate(label: "Test 521 EC Key")
    defer { try? ecKeyPair.delete() }

    _ = try SecKeyPair.import(fromData: ecKeyPair.export())
  }

  func testCodable() throws {

    let rsaData = try JSONEncoder().encode(rsaKeyPair)
    let testRSAKeyPair = try JSONDecoder().decode(SecKeyPair.self, from: rsaData)
    XCTAssertEqual(testRSAKeyPair.privateKey, rsaKeyPair.privateKey)
    XCTAssertEqual(testRSAKeyPair.publicKey, rsaKeyPair.publicKey)

    let ecData = try JSONEncoder().encode(ecKeyPair)
    let testECKeyPair = try JSONDecoder().decode(SecKeyPair.self, from: ecData)
    XCTAssertEqual(testECKeyPair.privateKey, ecKeyPair.privateKey)
    XCTAssertEqual(testECKeyPair.publicKey, ecKeyPair.publicKey)
  }

  func testGenerateSecureEnclave() throws {
#if os(macOS)
    try XCTSkipIf(true, "Code signing complexities require this to be disabled for macOS")
#else
    try XCTSkipUnless(SecureEnclave.isAvailable, "Only runs on iPhone/iPad/AppleTV")
#endif

    let keyPairBuilder = SecKeyPair.Builder(type: .ec, keySize: 256)

    var keyPair: SecKeyPair?
    XCTAssertNoThrow(keyPair = try keyPairBuilder.generate(label: "Test Secure Key", flags: [.secureEnclave]))
    XCTAssertNoThrow(try keyPair?.delete())
  }

  func testGeneratedSecureEnclave() throws {
#if os(macOS)
    try XCTSkipIf(true, "Code signing complexities require this to be disabled for macOS")
#else
    try XCTSkipUnless(SecureEnclave.isAvailable, "Only runs on iPhone/iPad/AppleTV")
#endif

    let ecKeyPair = try SecKeyPair.Builder(type: .ec, keySize: 256).generate(label: "Test Secure Enclave EC Key",
                                                                             flags: [.secureEnclave])
    defer { try? ecKeyPair.delete() }

    let privateKeyAttrs = [
      kSecAttrLabel: "Test Secure Enclave EC Key",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var privateKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(privateKeyAttrs, &privateKeyRef), errSecSuccess)
    XCTAssertNotNil(privateKeyRef)

    let publicKeyAttrs = [
      kSecAttrLabel: "Test Secure Enclave EC Key",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var publicKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(publicKeyAttrs as CFDictionary, &publicKeyRef), errSecSuccess)
    XCTAssertNotNil(publicKeyRef)
  }

}
