//
//  CryptorTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


/// Cryptor tests that execute roundtrip encryption/decryption for all
/// algorithms with every key size available using "awkward" update
/// buffer sizes.
///
/// As suggested by the name these tests are "padded" and use
/// plain-text buffers in numerous non block-size buffers .
///
class CryptorPaddedTests: ParameterizedTestCase {

  static let plainTextSizes = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 368, 512]

  static let bufferSize = 33
  static let bufferSize2 = 16

  var plainText: Data!
  var algorithm: Cryptor.Algorithm!
  var keySize: Int!

  override class var parameterSets: [Any] {
    var sets = [Any]()
    for plainTextSize in plainTextSizes {
      for algorithm in Cryptor.Algorithm.allCases {
        for keySize in algorithm.keySizes.testValues {
          sets.append((plainTextSize, algorithm, keySize))
        }
      }
    }
    return sets
  }

  override func setUpWithError() throws {
    guard let parameters = Self.parameterSets[parameterSetIdx ?? 0] as? (Int, Cryptor.Algorithm, Int) else {
      return XCTFail("Invalid Parameters")
    }
    let plainTextSize = parameters.0
    plainText = try Random.generate(count: plainTextSize)
    algorithm = parameters.1
    keySize = parameters.2
  }

  /// Tests encryption with padding enabled
  ///
  func testCryptorPadded() throws {
    let iv = try Random.generate(count: algorithm.blockSize)
    let key = try Random.generate(count: keySize)

    let encryptor = try Cryptor(.encrypt, using: algorithm, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(.decrypt, using: algorithm, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText, bufferSize: Self.bufferSize)

    XCTAssertEqual(
      cipherText,
      try Cryptor.encrypt(data: plainText, using: algorithm, options: [.pkcs7Padding], key: key, iv: iv)
    )
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText, bufferSize: Self.bufferSize2))
    XCTAssertEqual(
      plainText,
      try Cryptor.decrypt(data: cipherText, using: algorithm, options: [.pkcs7Padding], key: key, iv: iv)
    )
  }

}

/// Cryptor tests that execute roundtrip encryption/decryption for all
/// algorithms with every key size available using "awkward" update
/// buffer sizes.
///
/// As suggested by the name these tests are "unpadded" and use
/// a plain-text buffer equal to the algorithm's block-size.
///
class CryptorUnpaddedTests: ParameterizedTestCase {

  static let bufferSize = 33
  static let bufferSize2 = 16

  var plainText: Data!
  var algorithm: Cryptor.Algorithm!
  var keySize: Int!

  override class var parameterSets: [Any] {
    var sets = [Any]()
    for algorithm in Cryptor.Algorithm.allCases {
      for keySize in algorithm.keySizes.testValues {
        sets.append((algorithm, keySize))
      }
    }
    return sets
  }

  override func setUpWithError() throws {
    guard let parameters = Self.parameterSets[parameterSetIdx ?? 0] as? (Cryptor.Algorithm, Int) else {
      return XCTFail("Invalid Parameters")
    }
    algorithm = parameters.0
    keySize = parameters.1
    plainText = try Random.generate(count: algorithm.blockSize)
  }

  /// Tests encryption with padding disabled
  ///
  func testCryptorUnpadded() throws {
    let iv = try Random.generate(count: algorithm.blockSize)
    let key = try Random.generate(count: keySize)

    let encryptor = try Cryptor(.encrypt, using: algorithm, options: [], key: key, iv: iv)
    let decryptor = try Cryptor(.decrypt, using: algorithm, options: [], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText, bufferSize: Self.bufferSize)

    XCTAssertEqual(cipherText, try Cryptor.encrypt(data: plainText, using: algorithm, options: [], key: key, iv: iv))
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText, bufferSize: Self.bufferSize2))
    XCTAssertEqual(plainText, try Cryptor.decrypt(data: cipherText, using: algorithm, options: [], key: key, iv: iv))
  }

}

func exec(_ cryptor: Cryptor, source data: Data, bufferSize: Int) throws -> Data {

  var buffer = Data(repeating: 0, count: bufferSize + cryptor.blockSize)
  var result = Data()

  let totalBytes = data.count
  var totalBytesRead = 0

  while totalBytesRead < totalBytes {

    let bytesToRead = min(bufferSize, totalBytes - totalBytesRead)

    let processedBytes =
      try cryptor.update(data: data.subdata(in: totalBytesRead ..< (totalBytesRead + bytesToRead)), into: &buffer)

    result.append(buffer.prefix(upTo: processedBytes))
    totalBytesRead += bytesToRead
  }

  let processedBytes = try cryptor.final(into: &buffer)
  result.append(buffer.prefix(upTo: processedBytes))

  return result
}

extension Array where Element == Int {

  var testValues: [Int] {
    if count <= 64 {
      return self
    }
    else {
      return [first!, last!] + (1 ... 62).compactMap { _ in randomElement() }
    }
  }

}
