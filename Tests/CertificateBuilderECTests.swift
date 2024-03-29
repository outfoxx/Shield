//
//  CertificateBuilderECTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import PotentASN1
@testable import Shield
import ShieldOID
import XCTest

class CertificateBuilderECTests: XCTestCase {

  static let outputEnabled = false
  var keyPair: SecKeyPair!

  override func setUpWithError() throws {
    keyPair = try generateTestKeyPairChecked(type: .ec, keySize: 256, flags: [])
  }

  override func tearDownWithError() throws {
    try? keyPair?.delete()
  }

  func testBuildVer1() throws {

    let subject = try NameBuilder().add("Shield Subject", forTypeName: "CN").add("12345", forTypeName: "UID").name
    let issuer = try NameBuilder().add("Shield CA", forTypeName: "CN").name

    let cert =
      try Certificate.Builder()
        .subject(name: subject)
        .publicKey(keyPair: keyPair)
        .issuer(name: issuer)
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertEqual(cert.tbsCertificate.version, .v1)
    XCTAssertEqual(cert, try ASN1Decoder.decode(Certificate.self, from: cert.encoded()))
    XCTAssertNotNil(SecCertificateCreateWithData(nil, try cert.encoded() as CFData))
  }

  func testBuildVer2s() throws {

    let subject = try NameBuilder().add("Shield Subject", forTypeName: "CN").name
    let subjectID = try Random.generate(count: 10)
    let issuer = try NameBuilder().add("Shield CA", forTypeName: "CN").name

    let cert =
      try Certificate.Builder()
        .subject(name: subject, uniqueID: subjectID)
        .publicKey(keyPair: keyPair)
        .issuer(name: issuer)
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertEqual(cert.tbsCertificate.version, .v2)
    XCTAssertEqual(cert.tbsCertificate.subjectUniqueID, subjectID)
    XCTAssertEqual(cert, try ASN1Decoder.decode(Certificate.self, from: cert.encoded()))
    XCTAssertNotNil(SecCertificateCreateWithData(nil, try cert.encoded() as CFData))
  }

  func testBuildVer2i() throws {

    let subject = try NameBuilder().add("Shield Subject", forTypeName: "CN").name
    let issuer = try NameBuilder().add("Shield CA", forTypeName: "CN").name
    let issuerID = try Random.generate(count: 10)

    let cert =
      try Certificate.Builder()
        .subject(name: subject)
        .publicKey(keyPair: keyPair)
        .issuer(name: issuer, uniqueID: issuerID)
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertEqual(cert.tbsCertificate.version, .v2)
    XCTAssertEqual(cert.tbsCertificate.issuerUniqueID, issuerID)
    XCTAssertEqual(cert, try ASN1Decoder.decode(Certificate.self, from: cert.encoded()))
    XCTAssertNotNil(SecCertificateCreateWithData(nil, try cert.encoded() as CFData))
  }

  func testBuildVer2si() throws {

    let subject = try NameBuilder().add("Shield Subject", forTypeName: "CN").name
    let subjectID = try Random.generate(count: 10)
    let issuer = try NameBuilder().add("Shield CA", forTypeName: "CN").name
    let issuerID = try Random.generate(count: 10)

    let cert =
      try Certificate.Builder()
        .subject(name: subject, uniqueID: subjectID)
        .publicKey(keyPair: keyPair)
        .issuer(name: issuer, uniqueID: issuerID)
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertEqual(cert.tbsCertificate.version, .v2)
    XCTAssertEqual(cert.tbsCertificate.subjectUniqueID, subjectID)
    XCTAssertEqual(cert.tbsCertificate.issuerUniqueID, issuerID)
    XCTAssertEqual(cert, try ASN1Decoder.decode(Certificate.self, from: cert.encoded()))
    XCTAssertNotNil(SecCertificateCreateWithData(nil, try cert.encoded() as CFData))
  }

  func testBuildVer3() throws {

    let subject = try NameBuilder().add("Shield Subject", forTypeName: "CN").name
    let subjectID = try Random.generate(count: 10)
    let issuer = try NameBuilder().add("Shield CA", forTypeName: "CN").name
    let issuerID = try Random.generate(count: 10)

    let cert =
      try Certificate.Builder()
        .subject(name: subject, uniqueID: subjectID)
        .addSubjectAlternativeNames(names: .dnsName("github.com/outfoxx/Shield"))
        .publicKey(keyPair: keyPair)
        .extendedKeyUsage(
          keyPurposes: [iso.org.dod.internet.security.mechanisms.pkix.kp.serverAuth.oid],
          isCritical: false
        )
        .issuer(name: issuer, uniqueID: issuerID)
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertEqual(cert.tbsCertificate.version, .v3)
    XCTAssertEqual(cert.tbsCertificate.subjectUniqueID, subjectID)
    XCTAssertEqual(cert.tbsCertificate.issuerUniqueID, issuerID)
    XCTAssertEqual(cert, try ASN1Decoder.decode(Certificate.self, from: cert.encoded()))
    XCTAssertNotNil(SecCertificateCreateWithData(nil, try cert.encoded() as CFData))
  }

  func testBuildVer3NoUniqueIDs() throws {

    let subject = try NameBuilder().add("Shield Subject", forTypeName: "CN").name
    let issuer = try NameBuilder().add("Shield CA", forTypeName: "CN").name

    let cert =
      try Certificate.Builder()
        .subject(name: subject)
        .addSubjectAlternativeNames(names: .dnsName("github.com/outfoxx/Shield"))
        .publicKey(keyPair: keyPair)
        .issuer(name: issuer)
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertEqual(cert.tbsCertificate.version, .v3)
    XCTAssertEqual(cert, try ASN1Decoder.decode(Certificate.self, from: cert.encoded()))
    XCTAssertNotNil(SecCertificateCreateWithData(nil, try cert.encoded() as CFData))
  }

  func testBuildCA() throws {

    let subject = try NameBuilder().add("Shield Subject", forTypeName: "CN").name
    let subjectID = try Random.generate(count: 10)
    let issuer = try NameBuilder().add("Shield CA", forTypeName: "CN").name
    let issuerID = try Random.generate(count: 10)

    let cert =
      try Certificate.Builder()
        .subject(name: subject, uniqueID: subjectID)
        .addSubjectAlternativeNames(names: .dnsName("github.com/outfoxx/Shield"))
        .publicKey(keyPair: keyPair)
        .issuer(name: issuer, uniqueID: issuerID)
        .addIssuerAlternativeNames(names: .dnsName("github.com/outfoxx/Shield/CA"))
        .basicConstraints(ca: true)
        .authorityKeyIdentifier(
          Digester.digest(keyPair.encodedPublicKey(), using: .sha1),
          certIssuer: [.dnsName("github.com/outfoxx/Shield/CA")],
          certSerialNumber: Certificate.Builder.randomSerialNumber()
        )
        .computeSubjectKeyIdentifier()
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertEqual(cert.tbsCertificate.version, .v3)
    XCTAssertEqual(cert.tbsCertificate.subject, subject)
    XCTAssertEqual(cert.tbsCertificate.subjectUniqueID, subjectID)
    XCTAssertEqual(cert.tbsCertificate.issuer, issuer)
    XCTAssertEqual(cert.tbsCertificate.issuerUniqueID, issuerID)
    XCTAssertEqual(cert, try ASN1Decoder.decode(Certificate.self, from: cert.encoded()))
    XCTAssertNotNil(SecCertificateCreateWithData(nil, try cert.encoded() as CFData))
  }

  func testBuildFromRequestNoExtensions() throws {

    let csrData =
      try CertificationRequest.Builder()
        .subject(name: NameBuilder().add("Shield Subject", forTypeName: "CN").name)
        .publicKey(keyPair: keyPair)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let csr = try ASN1Decoder.decode(CertificationRequest.self, from: csrData)
    output(csr)

    XCTAssertNil(try csr.certificationRequestInfo.attributes?.first(Extensions.self))

    let cert =
      try Certificate.Builder()
        .request(csr)
        .issuer(name: csr.certificationRequestInfo.subject)
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertNil(cert.tbsCertificate.extensions)
  }

  func testBuildFromRequestWithExtensions() throws {

    let altNames: [GeneralName] = [.dnsName("github.com/outfoxx/Shield")]

    let csrData =
      try CertificationRequest.Builder()
        .subject(name: NameBuilder().add("Shield Subject", forTypeName: "CN").name)
        .addAlternativeNames(names: altNames)
        .publicKey(keyPair: keyPair, usage: [.dataEncipherment])
        .extendedKeyUsage(
          keyPurposes: [iso.org.dod.internet.security.mechanisms.pkix.kp.serverAuth.oid],
          isCritical: false
        )
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let csr = try ASN1Decoder.decode(CertificationRequest.self, from: csrData)
    output(csr)

    XCTAssertNotNil(try csr.certificationRequestInfo.attributes?.first(Extensions.self))

    let cert =
      try Certificate.Builder()
        .request(csr)
        .issuer(name: csr.certificationRequestInfo.subject)
        .valid(for: 86400 * 365)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(cert)

    XCTAssertNotNil(cert.tbsCertificate.extensions)
    XCTAssertEqual(try cert.tbsCertificate.extensions?.first(SubjectAltName.self), .init(names: altNames))
  }

  func output(_ value: Encodable & SchemaSpecified) {
    guard Self.outputEnabled else { return }
    guard let data = try? value.encoded().base64EncodedString() else { return }
    print(data)
  }

}
