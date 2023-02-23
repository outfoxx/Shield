//
//  ExtensionsTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Shield
import ShieldOID
import PotentASN1
import XCTest

class ExtensionsTests: XCTestCase {

  func testInitAnyExtensionValue() throws {

    let clientAuthOID = iso.org.dod.internet.security.mechanisms.pkix.kp.clientAuth.oid

    let ext = try Extension(value: ExtKeyUsage(keyPurposes: [clientAuthOID]), critical: true)
    let value = try ASN1Decoder(schema: ExtKeyUsage.asn1Schema).decode(ExtKeyUsage.self, from: ext.extnValue)
    XCTAssertEqual(value.keyPurposes, [clientAuthOID])
  }

  func testInitCriticalExtensionValue() throws {

    let ext = try Extension(value: BasicConstraints(ca: true, pathLenConstraint: 3))
    let value = try ASN1Decoder(schema: BasicConstraints.asn1Schema).decode(BasicConstraints.self, from: ext.extnValue)
    XCTAssertEqual(value.ca, true)
    XCTAssertEqual(value.pathLenConstraint, 3)
  }

  func testInitNonCriticalExtensionValue() throws {

    let ext = try Extension(value: SubjectAltName(names: [.dnsName("example.com")]))
    let value = try ASN1Decoder(schema: SubjectAltName.asn1Schema).decode(SubjectAltName.self, from: ext.extnValue)
    XCTAssertEqual(value.names, [.dnsName("example.com")])
  }

  func testGetAllExtensionValuessOfTypeFromExtensions() throws {

    var exts = Extensions()
    try exts.append(value: SubjectAltName(names: [.dnsName("example.com")]))
    try exts.append(value: SubjectAltName(names: [.dnsName("test.example.com")]))

    let values = try exts.all(SubjectAltName.self)
    XCTAssertEqual(values.count, 2)
    XCTAssertEqual(values.first?.names, [.dnsName("example.com")])
    XCTAssertEqual(values.last?.names, [.dnsName("test.example.com")])
  }

  func testRemoveExtensionValuesOfTypeFromExtensions() throws {

    var exts = Extensions()
    try exts.append(value: SubjectAltName(names: [.dnsName("example.com")]))
    try exts.append(value: SubjectAltName(names: [.dnsName("test.example.com")]))
    try exts.append(value: BasicConstraints(ca: true))

    exts.remove(SubjectAltName.self)

    XCTAssertEqual(exts.count, 1)
    XCTAssertNotNil(try exts.first(BasicConstraints.self))
  }

  func testAppendAnyExtensionValueToExtensions() throws {

    let clientAuthOID = iso.org.dod.internet.security.mechanisms.pkix.kp.clientAuth.oid

    var exts = Extensions()
    try exts.append(value: ExtKeyUsage(keyPurposes: [clientAuthOID]), isCritical: true)

    XCTAssertTrue(exts[0].critical)

    guard let ext = try exts.first(ExtKeyUsage.self) else {
      return XCTFail("Missing Extension")
    }
    XCTAssertEqual(ext.keyPurposes, [clientAuthOID])
  }

  func testReplaceAnyExtensionValuToExtensionse() throws {

    let clientAuthOID = iso.org.dod.internet.security.mechanisms.pkix.kp.clientAuth.oid
    let serverAuthOID = iso.org.dod.internet.security.mechanisms.pkix.kp.serverAuth.oid

    var exts = Extensions()
    try exts.append(value: ExtKeyUsage(keyPurposes: [clientAuthOID]), isCritical: true)
    try exts.replace(value: ExtKeyUsage(keyPurposes: [serverAuthOID]), isCritical: false)

    XCTAssertFalse(exts[0].critical)

    guard let ext = try exts.first(ExtKeyUsage.self) else {
      return XCTFail("Missing Extension")
    }
    XCTAssertEqual(ext.keyPurposes, [serverAuthOID])
  }

  func testAppendCriticalExtensionValueToExtensions() throws {

    var exts = Extensions()
    try exts.append(value: BasicConstraints(ca: true, pathLenConstraint: 3))

    XCTAssertTrue(exts[0].critical)

    guard let ext = try exts.first(BasicConstraints.self) else {
      return XCTFail("Missing Extension")
    }
    XCTAssertEqual(ext.ca, true)
    XCTAssertEqual(ext.pathLenConstraint, 3)
  }

  func testReplaceCriticalExtensionValueToExtensions() throws {

    var exts = Extensions()
    try exts.append(value: BasicConstraints(ca: true, pathLenConstraint: 3))
    try exts.replace(value: BasicConstraints(ca: false, pathLenConstraint: 2))

    XCTAssertTrue(exts[0].critical)

    guard let ext = try exts.first(BasicConstraints.self) else {
      return XCTFail("Missing Extension")
    }
    XCTAssertEqual(ext.ca, false)
    XCTAssertEqual(ext.pathLenConstraint, 2)
  }

  func testAppendNonCriticalExtensionValueToExtensions() throws {

    var exts = Extensions()
    try exts.append(value: SubjectAltName(names: [.dnsName("test.example.com")]))

    XCTAssertFalse(exts[0].critical)

    guard let ext = try exts.first(SubjectAltName.self) else {
      return XCTFail("Missing Extension")
    }
    XCTAssertEqual(ext.names, [.dnsName("test.example.com")])
  }

  func testReplaceNonCriticalExtensionValueToExtensions() throws {

    var exts = Extensions()
    try exts.append(value: SubjectAltName(names: [.dnsName("test.example.com")]))
    try exts.replace(value: SubjectAltName(names: [.dnsName("example.com")]))

    XCTAssertFalse(exts[0].critical)

    guard let ext = try exts.first(SubjectAltName.self) else {
      return XCTFail("Missing Extension")
    }
    XCTAssertEqual(ext.names, [.dnsName("example.com")])
  }

}
