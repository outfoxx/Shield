//
//  SecCertificateTests.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest

class SecCertificateTests: XCTestCase {

  static var keyPair: SecKeyPair!
  
  override class func setUp() {
    // Keys are comparatively slow to generate... so we do it once
    keyPair  = try! SecKeyPair.Builder(type: .rsa, keySize: 2048).generate(label: "Test")
  }
  
  override class func tearDown() {
    try! keyPair.delete()
  }

  func testCertificateProperties() throws {

    let name = try NameBuilder().add("Unit Testing", forTypeName: "CN").name

    let certData =
      try Certificate.Builder()
        .subject(name: name)
        .issuer(name: name)
        .publicKey(keyPair: Self.keyPair, usage: [.keyEncipherment])
        .valid(for: 86400 * 5)
        .build(signingKey: Self.keyPair.privateKey, digestAlgorithm: .sha256)
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
        .publicKey(keyPair: Self.keyPair, usage: [.keyEncipherment])
        .valid(for: 86400 * 5)
        .build(signingKey: Self.keyPair.privateKey, digestAlgorithm: .sha256)
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
