//
//  SecKeyTests.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest

class SecKeyTests: ParameterizedTestCase {

  static let keyPairs = [
    try! SecKeyPair.Builder(type: .rsa, keySize: 2048).generate(label: "Test"),
    try! SecKeyPair.Builder(type: .ec, keySize: 256).generate(label: "Test")
  ]
  
  override class func tearDown() {
    parameterSets.forEach { try! ($0 as! SecKeyPair).delete() }
  }

  override class var parameterSets: [Any] { keyPairs }
  
  private var keyPair: SecKeyPair!
  
  override func setUp() {
    keyPair = Self.parameterSets[parameterSetIdx ?? 0] as? SecKeyPair
  }
  
  deinit {
    try? keyPair!.delete()
    keyPair = nil
  }

  func testFailedEncryptError() {

    do {
      _ = try keyPair.publicKey.encrypt(plainText: try Random.generate(count: 312), padding: .oaep)
      XCTFail("Encrypt should have thrown an error")
    }
    catch _ {}
  }

  func testFailedDecryptError() {

    do {
      _ = try keyPair.privateKey.decrypt(cipherText: try Random.generate(count: 312), padding: .oaep)
      XCTFail("Decrypt should have thrown an error")
    }
    catch _ {}
  }

  func testSignVerifySHA1() throws {

    let data = try Random.generate(count: 217)

    let signature = try keyPair.privateKey.sign(data: data, digestAlgorithm: .sha1)

    XCTAssertTrue(try keyPair.publicKey.verify(data: data,
                                               againstSignature: signature, digestAlgorithm: .sha1))
  }

  func testSignVerifySHA224() throws {

    let data = try Random.generate(count: 217)

    let signature = try keyPair.privateKey.sign(data: data, digestAlgorithm: .sha224)

    XCTAssertTrue(try keyPair.publicKey.verify(data: data,
                                               againstSignature: signature, digestAlgorithm: .sha224))
  }

  func testSignVerifySHA256() throws {

    let data = try Random.generate(count: 217)

    let signature = try keyPair.privateKey.sign(data: data, digestAlgorithm: .sha256)

    XCTAssertTrue(try keyPair.publicKey.verify(data: data,
                                               againstSignature: signature, digestAlgorithm: .sha256))
  }

  func testSignVerifySHA384() throws {

    let data = try Random.generate(count: 217)

    let signature = try keyPair.privateKey.sign(data: data, digestAlgorithm: .sha384)

    XCTAssertTrue(try keyPair.publicKey.verify(data: data,
                                               againstSignature: signature, digestAlgorithm: .sha384))
  }

  func testSignVerifySHA512() throws {

    let data = try Random.generate(count: 217)

    let signature = try keyPair.privateKey.sign(data: data, digestAlgorithm: .sha512)

    XCTAssertTrue(try keyPair.publicKey.verify(data: data,
                                               againstSignature: signature, digestAlgorithm: .sha512))
  }

  func testSignVerifyFailed() throws {

    let invalidSignature = try keyPair.privateKey.sign(data: try Random.generate(count: 217), digestAlgorithm: .sha1)

    XCTAssertFalse(try keyPair.publicKey.verify(data: try Random.generate(count: 217),
                                                againstSignature: invalidSignature, digestAlgorithm: .sha1))
  }

  func testEncodeDecode() throws {

    let encodedPublicKey = try keyPair.publicKey.encode()
    let decodedPublicKey = try SecKey.decode(fromData: encodedPublicKey,
                                             type: keyPair.publicKey.type() as CFString,
                                             class: kSecAttrKeyClassPublic)

    let encodedPrivateKey = try keyPair.privateKey.encode()
    let decodedPrivateKey = try SecKey.decode(fromData: encodedPrivateKey,
                                              type: keyPair.publicKey.type() as CFString,
                                              class: kSecAttrKeyClassPrivate)

    guard try keyPair.publicKey.keyType() != .ec else {
      return
    }

    let plainText = try Random.generate(count: 143)

    let cipherText1 = try keyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)

    let cipherText2 = try decodedPublicKey.encrypt(plainText: plainText, padding: .oaep)

    XCTAssertEqual(plainText, try decodedPrivateKey.decrypt(cipherText: cipherText1, padding: .oaep))
    XCTAssertEqual(plainText, try decodedPrivateKey.decrypt(cipherText: cipherText2, padding: .oaep))
  }

  func testEncryptDecrypt() throws {
    try XCTSkipIf(keyPair.publicKey.keyType() == .ec)

    let plainText = try Random.generate(count: 171)
    
    let cipherText = try keyPair.publicKey.encrypt(plainText: plainText, padding: .oaep)
    
    let plainText2 = try keyPair.privateKey.decrypt(cipherText: cipherText, padding: .oaep)
    
    XCTAssertEqual(plainText, plainText2)
  }
  
}
