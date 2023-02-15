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
class CryptorPaddedTests: XCTestCase {

  static let plainTextSizes = [0, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 368, 512]

  static let bufferSize = 33
  static let bufferSize2 = 16

  /// Tests encryption with padding enabled
  ///
  func testCryptorPadded() throws {
    try Self.plainTextSizes.forEach { plainTextSize in
      let plainText = try Random.generate(count: plainTextSize)

      try Cryptor.Algorithm.allCases.forEach { algorithm in

        try algorithm.keySizes.testValues.forEach { keySize in

          print("Checking: plainText=\(plainTextSize) bytes, algorithm=\(algorithm), keySize=\(keySize)")

          try testCryptorPadded(plainText: plainText, algorithm: algorithm, keySize: keySize)

        }
      }
    }
  }

  func testCryptorPadded(plainText: Data, algorithm: Cryptor.Algorithm, keySize: Int) throws {
    let iv = try Random.generate(count: algorithm.blockSize)
    let key = try Random.generate(count: keySize)

    let encryptor = try Cryptor(.encrypt, using: algorithm, options: [.pkcs7Padding], key: key, iv: iv)
    let decryptor = try Cryptor(.decrypt, using: algorithm, options: [.pkcs7Padding], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText, bufferSize: Self.bufferSize)

    XCTAssertEqual(
      cipherText,
      try Cryptor.encrypt(data: plainText, using: algorithm, options: [.pkcs7Padding], key: key, iv: iv),
      "Encrypt failed for plainText = \(plainText.count) bytes, algorithm = \(algorithm.name), keySize = \(keySize)"
    )
    XCTAssertEqual(plainText, try exec(decryptor, source: cipherText, bufferSize: Self.bufferSize2))
    XCTAssertEqual(
      plainText,
      try Cryptor.decrypt(data: cipherText, using: algorithm, options: [.pkcs7Padding], key: key, iv: iv),
      "Decrypt failed for plainText = \(plainText.count) bytes, algorithm = \(algorithm.name), keySize = \(keySize)"
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
class CryptorUnpaddedTests: XCTestCase {

  static let bufferSize = 33
  static let bufferSize2 = 16

  /// Tests encryption with padding disabled
  ///
  func testCryptorUnpadded() throws {
    try Cryptor.Algorithm.allCases.forEach { algorithm in
      let plainText = try Random.generate(count: algorithm.blockSize)

      try algorithm.keySizes.testValues.forEach { keySize in

        print("Checking: algorithm=\(algorithm), keySize=\(keySize)")

        try testCryptorUnpadded(plainText: plainText, algorithm: algorithm, keySize: keySize)

      }
    }
  }

  func testCryptorUnpadded(plainText: Data, algorithm: Cryptor.Algorithm, keySize: Int) throws {
    let iv = try Random.generate(count: algorithm.blockSize)
    let key = try Random.generate(count: keySize)

    let encryptor = try Cryptor(.encrypt, using: algorithm, options: [], key: key, iv: iv)
    let decryptor = try Cryptor(.decrypt, using: algorithm, options: [], key: key, iv: iv)

    let cipherText = try exec(encryptor, source: plainText, bufferSize: Self.bufferSize)

    XCTAssertEqual(
      cipherText,
      try Cryptor.encrypt(data: plainText, using: algorithm, options: [], key: key, iv: iv),
      "Encrypt failed for algorithm = \(algorithm.name), keySize = \(keySize)"
    )
    XCTAssertEqual(
      plainText,
      try exec(decryptor, source: cipherText, bufferSize: Self.bufferSize2),
      "Exec failed for algorithm = \(algorithm.name), keySize = \(keySize)"
    )
    XCTAssertEqual(
      plainText,
      try Cryptor.decrypt(data: cipherText, using: algorithm, options: [], key: key, iv: iv),
      "Decrypt failed for algorithm = \(algorithm.name), keySize = \(keySize)"
    )
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
