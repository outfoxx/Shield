//
//  SecIdentityBuilderTests.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


class SecIdentityBuilderTests: XCTestCase {

  func testBuildAndFetch() throws {

    let subject: Name = try NameBuilder()
      .add("Test Guy", forTypeName: "CN")
      .add("Test Corp", forTypeName: "O")
      .add("TC", forTypeName: "C")
      .name

    let builder = try SecIdentityBuilder.generate(subject: subject,
                                                  keySize: 2048,
                                                  usage: .nonRepudiation)

    // Build a self-signed certificate for importing
    let certData =
      try Certificate.Builder()
        .subject(name: subject)
        .issuer(name: subject)
        .publicKey(keyPair: builder.keyPair, usage: [.nonRepudiation])
        .valid(for: 86400 * 5)
        .build(signingKey: builder.keyPair.privateKey, digestAlgorithm: .sha256)
        .encoded()

    let cert = SecCertificateCreateWithData(nil, certData as CFData)!

    // Save the certificate to finish out the identity
    try builder.save(withCertificate: cert)

    // Ensure all went well
    let ident = try SecIdentity.load(certificate: cert)

    XCTAssertNotNil(ident)
    XCTAssertNotNil(try ident.certificate())
    XCTAssertNotNil(try ident.privateKey())
  }

}
