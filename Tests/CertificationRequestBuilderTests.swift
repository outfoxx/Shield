//
//  CertificationRequestBuilderTests.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import PotentASN1
import ShieldOID
@testable import Shield
import XCTest

class CertificationRequestBuilderTests: XCTestCase {

  static let outputEnabled = false
  static var keyPair: SecKeyPair!
  
  override class func setUp() {
    // Keys are comparatively slow to generate... so we do it once
    keyPair  = try! SecKeyPair.Builder(type: .rsa, keySize: 2048).generate(label: "Test")
  }
  
  override class func tearDown() {
    try! keyPair.delete()
  }

  func testBuildParse() throws {
    
    let kp = iso.org.dod.internet.security.mechanisms.pkix.kp.self
    let csr =
      try CertificationRequest.Builder()
        .subject(name: NameBuilder().add("Outfox Signing", forTypeName: "CN").name)
        .alternativeNames(names: .dnsName("outfoxx.io"))        
        .publicKey(keyPair: Self.keyPair, usage: [.keyCertSign, .cRLSign])
        .extendedKeyUsage(keyPurposes: [kp.clientAuth.oid, kp.serverAuth.oid], isCritical: true)
        .build(signingKey: Self.keyPair.privateKey, digestAlgorithm: .sha256)

    output(csr)

    let csr2 = try ASN1Decoder.decode(CertificationRequest.self, from: csr.encoded())
    XCTAssertEqual(csr, csr2)

    let csrAttrs = csr.certificationRequestInfo.attributes
    XCTAssertEqual(try csrAttrs.first(Extensions.self)?.first(KeyUsage.self), [.keyCertSign, .cRLSign])
    XCTAssertEqual(try csrAttrs.first(Extensions.self)?.first(SubjectAltName.self), .init(names: [.dnsName("outfoxx.io")]))
  }

  func output(_ value: Encodable & SchemaSpecified) {
    guard Self.outputEnabled else { return }
    guard let data = try? value.encoded().base64EncodedString() else { return }
    print(data)
  }

}
