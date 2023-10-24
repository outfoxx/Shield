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
  var keyPair: SecKeyPair!

  override func setUpWithError() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [])
  }

  override func tearDownWithError() throws {
    try? keyPair?.delete()
  }

  func testAttributesFailForNonPermanentCerts() throws {

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
        .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let cert = try SecCertificate.from(data: certData)
    XCTAssertThrowsError(try cert.attributes())
  }

  func testSaveAcccessibilityUnlockedNotShared() throws {

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
        .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    output(certData)

    let cert = try SecCertificate.from(data: certData)
    defer { try? cert.delete() }

    do {
      try cert.save(accessibility: .unlocked(afterFirst: true, shared: false))
    }
    catch SecCertificateError.saveFailed {
      #if os(macOS)
      throw XCTSkip("Missing keychain entitlement")
      #endif
    }

    let attrs = try cert.attributes()
    XCTAssertEqual(attrs[kSecAttrAccessible as String] as? String, kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
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
        .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    output(certData)

    let cert = try SecCertificate.from(data: certData)

    XCTAssertTrue(subjectName == cert.subjectName!)
    XCTAssertTrue(issuerName == cert.issuerName!)
  }

  func testGetPublicKey() throws {

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
        .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    output(certData)

    let cert = try SecCertificate.from(data: certData)

    XCTAssertEqual(try cert.publicKey?.encode(), try keyPair.publicKey.encode())
  }

  func testPEM() throws {

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
        .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let certSec = try SecCertificate.from(data: certData)
    let certPem = certSec.pemEncoded

    XCTAssertEqual(certSec.derEncoded, try SecCertificate.load(pem: certPem).first?.derEncoded)
  }

  func testDER() throws {

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
        .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let certSec = try SecCertificate.from(data: certData)
    let certDer = certSec.derEncoded

    XCTAssertEqual(certSec.derEncoded, try SecCertificate.load(der: certDer).derEncoded)
  }

  func testCheckTrust() throws {

    let rootName = try NameBuilder().add("Unit Testing Root", forTypeName: "CN").name
    let rootID = try Random.generate(count: 10)
    let rootSerialNumber = try Certificate.Builder.randomSerialNumber()
    let rootKeyHash = try Digester.digest(keyPair.encodedPublicKey(), using: .sha1)
    let rootCertData =
    try Certificate.Builder()
      .serialNumber(rootSerialNumber)
      .subject(name: rootName, uniqueID: rootID)
      .subjectAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
      .subjectKeyIdentifier(rootKeyHash)
      .issuer(name: rootName)
      .issuerAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .basicConstraints(ca: true)
      .valid(for: 86400 * 5)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
      .encoded()
    output(rootCertData)

    let rootCert = try SecCertificate.from(data: rootCertData)

    let certKeyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])
    defer { try? certKeyPair.delete() }

    let certName = try NameBuilder().add("Unit Testing", forTypeName: "CN").name
    let certID = try Random.generate(count: 10)

    let certData =
    try Certificate.Builder()
      .serialNumber(Certificate.Builder.randomSerialNumber())
      .subject(name: certName, uniqueID: certID)
      .subjectAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.cert"))
      .publicKey(keyPair: certKeyPair, usage: [.keyEncipherment, .digitalSignature])
      .computeSubjectKeyIdentifier()
      .issuer(name: rootName)
      .issuerAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .authorityKeyIdentifier(rootKeyHash, certIssuer: [.directoryName(rootName)], certSerialNumber: rootSerialNumber)
      .valid(for: 86400 * 5)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
      .encoded()
    output(certData)


    let cert = try SecCertificate.from(data: certData)

    XCTAssertNoThrow(try cert.checkTrust(trustedCertificates: [rootCert]))
  }

  func testValidatedPublicKey() throws {

    let rootName = try NameBuilder().add("Unit Testing Root", forTypeName: "CN").name
    let rootID = try Random.generate(count: 10)
    let rootSerialNumber = try Certificate.Builder.randomSerialNumber()
    let rootKeyHash = try Digester.digest(keyPair.encodedPublicKey(), using: .sha1)
    let rootCertData =
    try Certificate.Builder()
      .serialNumber(rootSerialNumber)
      .subject(name: rootName, uniqueID: rootID)
      .subjectAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
      .subjectKeyIdentifier(rootKeyHash)
      .issuer(name: rootName)
      .issuerAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .basicConstraints(ca: true)
      .valid(for: 86400 * 5)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
      .encoded()
    output(rootCertData)

    let rootCert = try SecCertificate.from(data: rootCertData)

    let certKeyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])
    defer { try? certKeyPair.delete() }

    let certName = try NameBuilder().add("Unit Testing", forTypeName: "CN").name
    let certID = try Random.generate(count: 10)

    let certData =
    try Certificate.Builder()
      .serialNumber(Certificate.Builder.randomSerialNumber())
      .subject(name: certName, uniqueID: certID)
      .subjectAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.cert"))
      .publicKey(keyPair: certKeyPair, usage: [.keyEncipherment, .digitalSignature])
      .computeSubjectKeyIdentifier()
      .issuer(name: rootName)
      .issuerAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .authorityKeyIdentifier(rootKeyHash, certIssuer: [.directoryName(rootName)], certSerialNumber: rootSerialNumber)
      .valid(for: 86400 * 5)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
      .encoded()
    output(certData)


    let cert = try SecCertificate.from(data: certData)

    let finishedX = expectation(description: "finished")

    DispatchQueue.global(qos: .userInitiated).async {
      defer { finishedX.fulfill() }
      do {

        let publicKey = try cert.publicKeyValidated(trustedCertificates: [rootCert])
        XCTAssertEqual(try publicKey.encode(), try certKeyPair.publicKey.encode())

      }
      catch {
        XCTFail("\(error)")
      }
    }

    waitForExpectations(timeout: 10.0)
  }

#if swift(>=5.5)
  func testCheckTrustAsync() async throws {

    let rootName = try NameBuilder().add("Unit Testing Root", forTypeName: "CN").name
    let rootID = try Random.generate(count: 10)
    let rootSerialNumber = try Certificate.Builder.randomSerialNumber()
    let rootKeyHash = try Digester.digest(keyPair.encodedPublicKey(), using: .sha1)
    let rootCertData =
    try Certificate.Builder()
      .serialNumber(rootSerialNumber)
      .subject(name: rootName, uniqueID: rootID)
      .subjectAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
      .subjectKeyIdentifier(rootKeyHash)
      .issuer(name: rootName)
      .issuerAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .basicConstraints(ca: true)
      .valid(for: 86400 * 5)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
      .encoded()
    output(rootCertData)

    let rootCert = try SecCertificate.from(data: rootCertData)

    let certKeyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])
    defer { try? certKeyPair.delete() }

    let certName = try NameBuilder().add("Unit Testing", forTypeName: "CN").name
    let certID = try Random.generate(count: 10)

    let certData =
    try Certificate.Builder()
      .serialNumber(Certificate.Builder.randomSerialNumber())
      .subject(name: certName, uniqueID: certID)
      .subjectAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.cert"))
      .publicKey(keyPair: certKeyPair, usage: [.keyEncipherment, .digitalSignature])
      .computeSubjectKeyIdentifier()
      .issuer(name: rootName)
      .issuerAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .authorityKeyIdentifier(rootKeyHash, certIssuer: [.directoryName(rootName)], certSerialNumber: rootSerialNumber)
      .valid(for: 86400 * 5)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
      .encoded()
    output(certData)


    let cert = try SecCertificate.from(data: certData)

    do {
      try await cert.checkTrust(trustedCertificates: [rootCert])
    }
    catch {
      XCTFail("Unexpected error: \(error)")
    }
  }

  func testValidatedPublicKeyAsync() async throws {

    let rootName = try NameBuilder().add("Unit Testing Root", forTypeName: "CN").name
    let rootID = try Random.generate(count: 10)
    let rootSerialNumber = try Certificate.Builder.randomSerialNumber()
    let rootKeyHash = try Digester.digest(keyPair.encodedPublicKey(), using: .sha1)
    let rootCertData =
    try Certificate.Builder()
      .serialNumber(rootSerialNumber)
      .subject(name: rootName, uniqueID: rootID)
      .subjectAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
      .subjectKeyIdentifier(rootKeyHash)
      .issuer(name: rootName)
      .issuerAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .basicConstraints(ca: true)
      .valid(for: 86400 * 5)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
      .encoded()
    output(rootCertData)

    let rootCert = try SecCertificate.from(data: rootCertData)

    let certKeyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])
    defer { try? certKeyPair.delete() }

    let certName = try NameBuilder().add("Unit Testing", forTypeName: "CN").name
    let certID = try Random.generate(count: 10)

    let certData =
    try Certificate.Builder()
      .serialNumber(Certificate.Builder.randomSerialNumber())
      .subject(name: certName, uniqueID: certID)
      .subjectAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.cert"))
      .publicKey(keyPair: certKeyPair, usage: [.keyEncipherment, .digitalSignature])
      .computeSubjectKeyIdentifier()
      .issuer(name: rootName)
      .issuerAlternativeNames(names: .dnsName("io.outfoxx.shield.tests.ca"))
      .authorityKeyIdentifier(rootKeyHash, certIssuer: [.directoryName(rootName)], certSerialNumber: rootSerialNumber)
      .valid(for: 86400 * 5)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
      .encoded()
    output(certData)


    let cert = try SecCertificate.from(data: certData)

    let publicKey = try await cert.publicKeyValidated(trustedCertificates: [rootCert])

    XCTAssertEqual(try publicKey.encode(), try certKeyPair.publicKey.encode())
  }
#endif

  func testValidatedPublicKeyWithInvalidCertificate() throws {

    let rootName = try NameBuilder().add("Unit Testing Root", forTypeName: "CN").name

    let rootCert = try SecCertificate.from(data:
      try Certificate.Builder()
        .subject(name: rootName)
        .issuer(name: rootName)
        .publicKey(keyPair: keyPair, usage: [.keyCertSign])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()
    )

    let certKeyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])
    defer { try? certKeyPair.delete() }

    let certName = try NameBuilder().add("Unit Testing", forTypeName: "CN").name

    let cert = try SecCertificate.from(data:
      try Certificate.Builder()
        .subject(name: certName)
        .issuer(name: rootName)
        .publicKey(keyPair: certKeyPair, usage: [.keyEncipherment])
        .valid(for: 86400 * 5)
        .build(signingKey: certKeyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()
    )

    let finishedX = expectation(description: "finished")

    DispatchQueue.global(qos: .userInitiated).async {
      defer { finishedX.fulfill() }
      do {
        _ = try cert.publicKeyValidated(trustedCertificates: [rootCert])
        XCTFail("Should have thrown error")
      }
      catch {
        guard let secError = error as? SecCertificateError, secError == .trustValidationFailed else {
          return XCTFail("Incorrect error received: \(error)")
        }
      }
    }

    waitForExpectations(timeout: 10.0)
  }

#if swift(>=5.5)
  func testValidatedPublicKeyAsyncWithInvalidCertificate() async throws {

    let rootName = try NameBuilder().add("Unit Testing Root", forTypeName: "CN").name

    let rootCert = try SecCertificate.from(data:
      try Certificate.Builder()
        .subject(name: rootName)
        .issuer(name: rootName)
        .publicKey(keyPair: keyPair, usage: [.keyCertSign])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()
    )

    let certKeyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])
    defer { try? certKeyPair.delete() }

    let certName = try NameBuilder().add("Unit Testing", forTypeName: "CN").name

    let cert = try SecCertificate.from(data:
      try Certificate.Builder()
        .subject(name: certName)
        .issuer(name: rootName)
        .publicKey(keyPair: certKeyPair, usage: [.keyEncipherment])
        .valid(for: 86400 * 5)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()
    )

    do {
      _ = try await cert.publicKeyValidated(trustedCertificates: [rootCert])
      XCTFail("Should have thrown error")
    }
    catch {
      guard let secError = error as? SecCertificateError, secError == .trustValidationFailed else {
        return XCTFail("Incorrect error received: \(error)")
      }
    }
  }
#endif

  func output(_ data: Data) {
    guard Self.outputEnabled else { return }
    print(data.base64EncodedString())
  }

}
