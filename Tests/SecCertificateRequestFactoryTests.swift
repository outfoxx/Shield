//
//  SecCertificateRequestFactoryTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


class SecCertificateRequestFactoryTests: XCTestCase {

  func testBuild() throws {

    let keyPair = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    let factory = SecCertificateRequestFactory()
    factory.subject = [[AttributeTypeAndValue<DirectoryNameAttributeMapper>(type: "CN", value: "Outfox Signing")]]
    factory.publicKey = try keyPair.encodedPublicKey()
    factory.keyUsage = [.keyEncipherment]

    let csrData = try factory.build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)
    fatalError()
    //    let csrDataEncoded = csrData.base64EncodedString()

//    let certFactory = SecCertificateFactory(requestInfo: csrData)
//    certFactory.issuer = factory.subject
//
//    let certData = try certFactory.build(signingKey: keyPair.privateKey, signingAlgorithm: .sha256)
//    let certDataEncoded = certData.base64EncodedString()
//
//    print(certDataEncoded)
  }

}
