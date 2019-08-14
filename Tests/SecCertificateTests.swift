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


// Keys are comparatively slow to generate... so we do it once
private let keyPair = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()


class SecCertificateTests: XCTestCase {

  func testCertificateProperties() throws {

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

    XCTAssertTrue(name == cert.issuerName!)
    XCTAssertTrue(name == cert.subjectName!)
  }

  func testInvalidCertificate() throws {

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

    do {
      _ = try cert.publicKeyValidated(trustedCertificates: [])
      XCTFail("Should have thrown an error")
    }
    catch {
      print(error)
    }
  }
}
