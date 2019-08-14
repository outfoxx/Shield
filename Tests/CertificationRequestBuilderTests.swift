//
//  CertificationRequestBuilderTests.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import PotentASN1
import XCTest


class CertificationRequestBuilderTests: XCTestCase {

  let outputEnabled = false

  func testBuild() throws {

    let keyPair = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    let csr =
      try CertificationRequest.Builder()
        .subject(name: NameBuilder().add("Outfox Signing", forTypeName: "CN").name)
        .alternativeNames(names: .dnsName("outfoxx.io"))
        .publicKey(keyPair: keyPair, usage: [.keyEncipherment])
        .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    output(csr)

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
