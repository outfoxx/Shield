//
//  SecCertificateTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest

class SecCertificateTests: XCTestCase {

  static let outputEnabled = false
  static var keyPair: SecKeyPair!

  override class func setUp() {
    // Keys are comparatively slow to generate... so we do it once
    guard let keyPair = try? SecKeyPair.Builder(type: .rsa, keySize: 2048).generate(label: "Test") else {
      return XCTFail("Key pair generation failed")
    }
    Self.keyPair = keyPair
  }

  override class func tearDown() {
    try? keyPair.delete()
  }

  func testCertificateProperties() throws {

    let subjectName = try NameBuilder()
      .add("Unit Testing", forTypeName: "CN")
      .add("123456", forTypeName: "UID")
      .name

    let issuerName = try NameBuilder()
      .add("Test Issuer", forTypeName: "CN")
      .name

    let certData =
      try Certificate.Builder()
        .subject(name: subjectName)
        .issuer(name: issuerName)
        .publicKey(keyPair: Self.keyPair, usage: [.keyCertSign, .cRLSign])
        .valid(for: 86400 * 5)
        .build(signingKey: Self.keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    output(certData)

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    XCTAssertTrue(subjectName == cert.subjectName!)
    XCTAssertTrue(issuerName == cert.issuerName!)
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

    XCTAssertThrowsError(try cert.publicKeyValidated(trustedCertificates: []))
  }

  func output(_ data: Data) {
    guard Self.outputEnabled else { return }
    print(data.base64EncodedString())
  }

}
