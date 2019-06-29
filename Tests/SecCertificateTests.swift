//
//  SecCertificateTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


class SecCertificateTests: XCTestCase {

  func testCertificateProperties() throws {

    let keyPairWithKeychain = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    let certFactory = SecCertificateFactory()
//    certFactory.subject = [("CN", "Unit Testing")]
    certFactory.issuer = certFactory.subject
//    certFactory.publicKeyInfo = try keyPairWithKeychain.encodedPublicKey()
    certFactory.keyUsage = [.keyEncipherment]

    let certData = try certFactory.build(signingKey: keyPairWithKeychain.privateKey, signingAlgorithm: .sha256)

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    let name: Name = [] //= X501.build(from: [X501NameEntry("CN", "Unit Testing")])
    XCTAssertTrue(name == cert.issuerName!)
    XCTAssertTrue(name == cert.subjectName!)
  }

  func testInvalidCertificate() throws {

    let keyPairWithKeychain = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    let certFactory = SecCertificateFactory()
//    certFactory.subject = [X501NameEntry("CN", "Unit Testing")]
    certFactory.issuer = certFactory.subject
//    certFactory.publicKey = try keyPairWithKeychain.encodedPublicKey()
    certFactory.keyUsage = [.keyEncipherment]

    let certData = try certFactory.build(signingKey: keyPairWithKeychain.privateKey, signingAlgorithm: .sha256)

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    do {
      _ = try cert.publicKeyValidated(trustedCertificates: [])
      XCTFail("Should have thrown an error")
    }
    catch {
      print(error)
    }
  }
}
