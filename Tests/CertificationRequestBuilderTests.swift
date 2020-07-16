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


// Keys are comparatively slow to generate... so we do it once
private let keyPair = try! SecKeyPair.Builder(type: .rsa, keySize: 2048).generate()


class CertificationRequestBuilderTests: XCTestCase {

  let outputEnabled = false

  func testBuildParse() throws {
    
    let kp = iso.org.dod.internet.security.mechanisms.pkix.kp.self
    let csr =
      try CertificationRequest.Builder()
        .subject(name: NameBuilder().add("Outfox Signing", forTypeName: "CN").name)
        .alternativeNames(names: .dnsName("outfoxx.io"))
        .publicKey(keyPair: keyPair, usage: [.keyEncipherment])
        .extendedKeyUsage(keyPurposes: [kp.clientAuth.oid, kp.serverAuth.oid], isCritical: true)
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(csr)

    let csr2 = try ASN1Decoder.decode(CertificationRequest.self, from: csr.encoded())
    XCTAssertEqual(csr, csr2)

    let csrAttrs = csr.certificationRequestInfo.attributes
    XCTAssertEqual(try csrAttrs.first(Extensions.self)?.first(KeyUsage.self), [.keyEncipherment])
    XCTAssertEqual(try csrAttrs.first(Extensions.self)?.first(SubjectAltName.self), .init(names: [.dnsName("outfoxx.io")]))
  }

  func output(_ value: Encodable & SchemaSpecified) {
    guard outputEnabled else { return }
    guard let data = try? value.encoded().base64EncodedString() else { return }
    print(data)
  }

}
