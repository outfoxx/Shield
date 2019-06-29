//
//  SecKeyPairTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


class SecKeyPairTests: XCTestCase {

  var keyPair: SecKeyPair!

  override func setUp() {
    super.setUp()

    keyPair = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()
  }

  func testPersistentLoad() throws {

    let (privateKeyRef, publicKeyRef) = try keyPair.persistentReferences()

    XCTAssertNotNil(try SecKeyPair(privateKeyRef: privateKeyRef, publicKeyRef: publicKeyRef))
  }

  func testCertificateMatching() throws {

    let certFactory = SecCertificateFactory()
//    certFactory.subject = [X501NameEntry("CN", "Unit Testing")]
    certFactory.issuer = certFactory.subject
//    certFactory.publicKey = try keyPair.encodedPublicKey()
    certFactory.keyUsage = [.keyEncipherment]

    let certData = try certFactory.build(signingKey: keyPair.privateKey, signingAlgorithm: .sha256)

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    XCTAssertTrue(try keyPair.matchesCertificate(certificate: cert, trustedCertificates: [cert]))
  }

  func testImportExport() throws {

    let exportedKeyData = try keyPair.export(password: "123")

    try keyPair.delete()

    let importedKeyPair = try SecKeyPair.importKeys(fromData: exportedKeyData, withPassword: "123")

    let plainText = try Random.generate(count: 171)

    let cipherText1 = try keyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText2 = try importedKeyPair.privateKey.decrypt(cipherText: cipherText1, padding: .oaep)

    XCTAssertEqual(plainText, plainText2)

    let cipherText2 = try importedKeyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText3 = try keyPair.privateKey.decrypt(cipherText: cipherText2, padding: .oaep)

    XCTAssertEqual(plainText, plainText3)
  }
}
