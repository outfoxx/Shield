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

  var keyPair: SecKeyPair!

  override func tearDownWithError() throws {
    try? keyPair?.delete()
  }

  func testGeneratedRSA() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048)

    let privateKeyAttrs = [
      kSecAttrLabel: "Test RSA Key Pair",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var privateKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(privateKeyAttrs, &privateKeyRef), errSecSuccess)
    XCTAssertNotNil(privateKeyRef)

    let publicKeyAttrs = [
      kSecAttrLabel: "Test RSA Key Pair",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var publicKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(publicKeyAttrs, &publicKeyRef), errSecSuccess)
    XCTAssertNotNil(publicKeyRef)
  }

  func testGeneratedEC() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256)

    let privateKeyAttrs = [
      kSecAttrLabel: "Test EC Key Pair",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var privateKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(privateKeyAttrs, &privateKeyRef), errSecSuccess)
    XCTAssertNotNil(privateKeyRef)

    let publicKeyAttrs = [
      kSecAttrLabel: "Test EC Key Pair",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var publicKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(publicKeyAttrs, &publicKeyRef), errSecSuccess)
    XCTAssertNotNil(publicKeyRef)
  }

  func testInitECFromExternalPrivateKey() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])

    let external = try keyPair.privateKey.encode()

    XCTAssertNoThrow(try SecKeyPair(type: keyPair.privateKey.keyType(), privateKeyData: external))
  }

  func testInitRSAFromExternalPrivateKey() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [])

    let external = try keyPair.privateKey.encode()

    XCTAssertNoThrow(try SecKeyPair(type: keyPair.privateKey.keyType(), privateKeyData: external))
  }

  func testPersistentLoadRSA() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [.permanent])

    let (privateKeyRef, publicKeyRef) = try keyPair.persistentReferences()

    XCTAssertNotNil(try SecKeyPair(privateKeyRef: privateKeyRef, publicKeyRef: publicKeyRef))
  }

  func testPersistentLoadEC() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [.permanent])

    let (privateKeyRef, publicKeyRef) = try keyPair.persistentReferences()

    XCTAssertNotNil(try SecKeyPair(privateKeyRef: privateKeyRef, publicKeyRef: publicKeyRef))
  }

  func testCertificateMatching() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [])

    let name = try NameBuilder().add("Unit Testing", forTypeName: "CN").name

    let certData =
      try Certificate.Builder()
        .subject(name: name)
        .issuer(name: name)
        .publicKey(keyPair: keyPair, usage: [.keyEncipherment])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    let finishedX = expectation(description: "finished")

    DispatchQueue.global(qos: .userInitiated).async {
      defer { finishedX.fulfill() }

      let result = self.keyPair.matchesCertificate(certificate: cert, trustedCertificates: [cert])

      XCTAssertTrue(result)
    }

    waitForExpectations(timeout: 10.0)
  }

#if swift(>=5.5)
  func testCertificateMatchingAsync() async throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [])

    let name = try NameBuilder().add("Unit Testing", forTypeName: "CN").name

    let certData =
      try Certificate.Builder()
        .subject(name: name)
        .issuer(name: name)
        .publicKey(keyPair: keyPair, usage: [.keyEncipherment])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    let result = await self.keyPair.matchesCertificate(certificate: cert, trustedCertificates: [cert])
    XCTAssertTrue(result)
  }
#endif

  func testImportExportEncryptedRSA() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [])

    let exportedKeyData = try keyPair.export(password: "123")

    let importedKeyPair = try SecKeyPair.import(data: exportedKeyData, password: "123")

    XCTAssertThrowsError(try SecKeyPair.import(data: exportedKeyData, password: "456"))

    let plainText = try Random.generate(count: 171)

    let cipherText1 = try keyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText2 = try importedKeyPair.privateKey.decrypt(cipherText: cipherText1, padding: .oaep)

    XCTAssertEqual(plainText, plainText2)

    let cipherText2 = try importedKeyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText3 = try keyPair.privateKey.decrypt(cipherText: cipherText2, padding: .oaep)

    XCTAssertEqual(plainText, plainText3)

    try? keyPair.delete()
    defer { keyPair = nil }

    let cipherText3 = try importedKeyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText4 = try importedKeyPair.privateKey.decrypt(cipherText: cipherText3, padding: .oaep)

    XCTAssertEqual(plainText, plainText4)

  }

  func testImportExportRSA() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [])

    let exportedKeyData = try keyPair.export()

    let importedKeyPair = try SecKeyPair.import(data: exportedKeyData)

    let plainText = try Random.generate(count: 171)

    let cipherText1 = try keyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText2 = try importedKeyPair.privateKey.decrypt(cipherText: cipherText1, padding: .oaep)

    XCTAssertEqual(plainText, plainText2)
  }

  func testImportExportEncryptedEC() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])

    let exportedKeyData = try keyPair.export(password: "123")

    _ = try SecKeyPair.import(data: exportedKeyData, password: "123")

    XCTAssertThrowsError(try SecKeyPair.import(data: exportedKeyData, password: "456"))
  }

  func testImportExportPEM() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])

    let exportedKeyData = try keyPair.exportPEM()

    XCTAssertNoThrow(try SecKeyPair.import(pem: exportedKeyData))
  }

  func testImportExportEncryptedPEM() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])

    let exportedKeyData = try keyPair.exportPEM(password: "123")

    _ = try SecKeyPair.import(pem: exportedKeyData, password: "123")

    XCTAssertThrowsError(try SecKeyPair.import(pem: exportedKeyData, password: "456"))
  }

  func testImportExportEC192() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 192, flags: [])

    XCTAssertThrowsError(try SecKeyPair.import(data: keyPair.export())) { error in
      XCTAssertTrue(error is AlgorithmIdentifier.Error)
    }
  }

  func testImportExportEC256() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])

    _ = try SecKeyPair.import(data: keyPair.export())
  }

  func testImportExportEC384() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 384, flags: [])

    _ = try SecKeyPair.import(data: keyPair.export())
  }

  func testImportExportEC521() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 521, flags: [])

    _ = try SecKeyPair.import(data: keyPair.export())
  }

  func testCodableRSA() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048)

    let rsaData = try JSONEncoder().encode(keyPair)
    let testKeyPair = try JSONDecoder().decode(SecKeyPair.self, from: rsaData)
    XCTAssertEqual(testKeyPair.privateKey, keyPair.privateKey)
    XCTAssertEqual(testKeyPair.publicKey, keyPair.publicKey)
  }

  func testCodableEC() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 521)

    let ecData = try JSONEncoder().encode(keyPair)
    let testKeyPair = try JSONDecoder().decode(SecKeyPair.self, from: ecData)
    XCTAssertEqual(testKeyPair.privateKey, keyPair.privateKey)
    XCTAssertEqual(testKeyPair.publicKey, keyPair.publicKey)
  }

  func testGenerateSecureEnclave() throws {
    try XCTSkipUnless(SecureEnclave.isAvailable, "Requires secure enclave")

    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [.secureEnclave])
  }

  func testGeneratedSecureEnclave() throws {
    try XCTSkipUnless(SecureEnclave.isAvailable, "Requires secure enclave")
#if os(macOS)
    try XCTSkipIf(true, "Code signing complexities require this to be disabled for macOS")
#endif

    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [.secureEnclave])

    let privateKeyAttrs = [
      kSecAttrLabel: "Test Secure Enclave EC Key Pair",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var privateKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(privateKeyAttrs, &privateKeyRef), errSecSuccess)
    XCTAssertNotNil(privateKeyRef)

    let publicKeyAttrs = [
      kSecAttrLabel: "Test Secure Enclave EC Key Pair",
      kSecClass: kSecClassKey,
      kSecAttrKeyClass: kSecAttrKeyClassPublic,
      kSecReturnRef: kCFBooleanTrue!,
    ] as [String: Any] as CFDictionary
    var publicKeyRef: CFTypeRef?
    XCTAssertEqual(SecItemCopyMatching(publicKeyAttrs, &publicKeyRef), errSecSuccess)
    XCTAssertNotNil(publicKeyRef)
  }

}
