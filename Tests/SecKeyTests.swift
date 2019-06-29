//
//  SecKeyTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


class SecKeyTests: XCTestCase {

  var publicKey: SecKey!
  var privateKey: SecKey!

  override func setUp() {
    super.setUp()

    let pair = try! SecKeyPairFactory(type: .RSA, keySize: 2048).generate()

    publicKey = pair.publicKey
    privateKey = pair.privateKey
  }


  func testEncryptDecrypt() throws {

    let plainText = try Random.generate(count: 171)

    let cipherText = try publicKey.encrypt(plainText: plainText, padding: .oaep)

    let plainText2 = try privateKey.decrypt(cipherText: cipherText, padding: .oaep)

    XCTAssertEqual(plainText, plainText2)
  }

  func testFailedEncryptError() {

    do {
      _ = try publicKey.encrypt(plainText: try Random.generate(count: 312), padding: .oaep)
      XCTFail("Encrypt should have thrown an error")
    }
    catch _ {}
  }

  func testFailedDecryptError() {

    do {
      _ = try privateKey.decrypt(cipherText: try Random.generate(count: 312), padding: .oaep)
      XCTFail("Decrypt should have thrown an error")
    }
    catch _ {}
  }

  func testSignVerifySHA1() throws {

    let data = try Random.generate(count: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .sha1)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .sha1))
  }

  func testSignVerifySHA224() throws {

    let data = try Random.generate(count: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .sha224)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .sha224))
  }

  func testSignVerifySHA256() throws {

    let data = try Random.generate(count: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .sha256)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .sha256))
  }

  func testSignVerifySHA384() throws {

    let data = try Random.generate(count: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .sha384)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .sha384))
  }

  func testSignVerifySHA512() throws {

    let data = try Random.generate(count: 217)

    let signature = try privateKey.sign(data: data, digestAlgorithm: .sha512)

    XCTAssertTrue(try publicKey.verify(data: data, againstSignature: signature, digestAlgorithm: .sha512))
  }

  func testSignVerifyFailed() throws {

    let invalidSignature = try privateKey.sign(data: try Random.generate(count: 217), digestAlgorithm: .sha1)

    XCTAssertFalse(try publicKey.verify(data: try Random.generate(count: 217), againstSignature: invalidSignature, digestAlgorithm: .sha1))
  }

  func testEncodeDecode() throws {

    let plainText = try Random.generate(count: 143)

    let cipherText1 = try publicKey.encrypt(plainText: plainText, padding: .oaep)

    let encodedPublicKey = try publicKey.encode(class: kSecAttrKeyClassPublic)
    let decodedPublicKey = try SecKey.decode(fromData: encodedPublicKey, type: kSecAttrKeyTypeRSA, class: kSecAttrKeyClassPublic)

    let cipherText2 = try decodedPublicKey.encrypt(plainText: plainText, padding: .oaep)

    let encodedPrivateKey = try privateKey.encode(class: kSecAttrKeyClassPrivate)
    let decodedPrivateKey = try SecKey.decode(fromData: encodedPrivateKey, type: kSecAttrKeyTypeRSA, class: kSecAttrKeyClassPrivate)

    XCTAssertEqual(plainText, try decodedPrivateKey.decrypt(cipherText: cipherText1, padding: .oaep))
    XCTAssertEqual(plainText, try decodedPrivateKey.decrypt(cipherText: cipherText2, padding: .oaep))
  }

}
