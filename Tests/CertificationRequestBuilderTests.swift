//
//  CertificationRequestBuilderTests.swift
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

class CertificationRequestBuilderTests: XCTestCase {

  static let outputEnabled = false
  var keyPair: SecKeyPair!

  override func setUpWithError() throws {
    keyPair = try generateTestKeyPairChecked(type: .rsa, keySize: 2048, flags: [])
  }

  override func tearDownWithError() throws {
    try? keyPair?.delete()
  }

  func testBuildParse() throws {

    let keyPurpose = iso.org.dod.internet.security.mechanisms.pkix.kp.self
    let csr =
      try CertificationRequest.Builder()
        .subject(name: NameBuilder().add("Outfox Signing", forTypeName: "CN").name)
        .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
        .extendedKeyUsage(keyPurposes: [keyPurpose.clientAuth.oid, keyPurpose.serverAuth.oid], isCritical: true)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(csr)


    let csr2 = try ASN1Decoder.decode(CertificationRequest.self, from: csr.encoded())
    XCTAssertEqual(csr, csr2)

    let csrAttrs = csr.certificationRequestInfo.attributes
    XCTAssertEqual(try csrAttrs?.first(Extensions.self)?.first(KeyUsage.self), [.keyCertSign, .cRLSign])
  }

  func testSANs() throws {

    let dirName = NameBuilder()
      .add("123", forType: iso_itu.ds.attributeType.title.oid)
      .name

    let sans: [GeneralName] = [
      .otherName(OtherName(typeId: [1, 3, 6, 1, 4, 1, 311, 20, 2, 3], value: .utf8String("123"))),
      .rfc822Name("test@example.com"),
      .dnsName("outfoxx.io"),
      .directoryName(dirName),
      .ediPartyName(EDIPartyName(nameAssigner: "test", partyName: "example")),
      .uniformResourceIdentifier("https://example.com"),
      .ipAddress(Data([1, 2, 3, 4])),
      .ipAddress(Data([10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160])),
      .registeredID(iso_itu.ds.attributeType.title.oid),
    ]

    let keyPurpose = iso.org.dod.internet.security.mechanisms.pkix.kp.self
    let csr =
      try CertificationRequest.Builder()
        .subject(name: NameBuilder().add("Outfox Signing", forTypeName: "CN").name)
        .addAlternativeNames(names: sans)
        .publicKey(keyPair: keyPair, usage: [.keyCertSign, .cRLSign])
        .extendedKeyUsage(keyPurposes: [keyPurpose.clientAuth.oid, keyPurpose.serverAuth.oid], isCritical: true)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(csr)

    let csr2 = try ASN1Decoder.decode(CertificationRequest.self, from: csr.encoded())
    XCTAssertEqual(csr, csr2)

    let csrExts = try csr.certificationRequestInfo.attributes?.first(Extensions.self)

    let csrSANs = try csrExts?.first(SubjectAltName.self)
    XCTAssertEqual(csrSANs?.names, sans)
  }

  func output(_ value: Encodable & SchemaSpecified) {
    guard Self.outputEnabled else { return }
    guard let data = try? value.encoded().base64EncodedString() else { return }
    print(data)
  }

}
