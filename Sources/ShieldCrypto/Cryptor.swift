//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/11/19.
//

import Foundation
import CommonCrypto.CommonCryptor


public class Cryptor {

  public struct Operation: RawRepresentable, Equatable, Hashable {
    public let rawValue: CCOperation

    public init(rawValue: CCOperation) {
      self.rawValue = rawValue
    }

    public static let encrypt = Operation(rawValue: UInt32(kCCEncrypt))
    public static let decrypt = Operation(rawValue: UInt32(kCCDecrypt))
  }

  public struct Algorithm: Equatable, Hashable, CaseIterable, CustomStringConvertible {
    public let rawValue: CCAlgorithm
    public let name: String

    public init(rawValue: CCAlgorithm, name: String) {
      self.rawValue = rawValue
      self.name = name
    }

    public var blockSize: Int {
      switch self {
      case .aes: return kCCBlockSizeAES128
      case .des: return kCCBlockSizeDES
      case .tripleDES: return kCCBlockSize3DES
      case .cast: return kCCBlockSizeCAST
      case .rc2: return kCCBlockSizeRC2
      case .rc4: return kCCBlockSizeRC2
      case .blowfish: return kCCBlockSizeBlowfish
      default:
        fatalError("unsupported algorithm")
      }
    }

    public var keySizes: [Int] {
      switch self {
      case .aes: return Array([kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256])
      case .des: return Array([kCCKeySizeDES])
      case .tripleDES: return Array([kCCKeySize3DES])
      case .cast: return Array(kCCKeySizeMinCAST ... kCCKeySizeMaxCAST)
      case .rc2: return Array(kCCKeySizeMinRC2 ... kCCKeySizeMaxRC2)
      case .rc4: return Array(kCCKeySizeMinRC4 ... kCCKeySizeMaxRC4)
      case .blowfish: return Array(kCCKeySizeMinBlowfish ... kCCKeySizeMaxBlowfish)
      default:
        fatalError("unsupported algorithm")
      }

    }

    public var description: String {
      return name
    }

    public static let aes = Algorithm(rawValue: UInt32(kCCAlgorithmAES), name: "AES")
    public static let des = Algorithm(rawValue: UInt32(kCCAlgorithmDES), name: "DES")
    public static let tripleDES = Algorithm(rawValue: UInt32(kCCAlgorithm3DES), name: "3DES")
    public static let cast = Algorithm(rawValue: UInt32(kCCAlgorithmCAST), name: "CAST")
    public static let rc2 = Algorithm(rawValue: UInt32(kCCAlgorithmRC2), name: "RC2")
    public static let rc4 = Algorithm(rawValue: UInt32(kCCAlgorithmRC4), name: "RC4")
    public static let blowfish = Algorithm(rawValue: UInt32(kCCAlgorithmBlowfish), name: "Blowfish")

    public static let allCases: [Algorithm] = [.aes, .des, .tripleDES, .cast, .rc2, .rc4, .blowfish]
  }

  public struct Options: OptionSet, Equatable, Hashable {
    public var rawValue: CCOptions

    public init(rawValue: CCOptions) {
      self.rawValue = rawValue
    }

    public static let pkcs7Padding = Options(rawValue: 1 << 0)
    public static let ecbMode = Options(rawValue: 1 << 1)

  }

  public let blockSize: Int
  private let ref: CCCryptorRef

  public init(_ operation: Operation, using algorithm: Algorithm, options: Options, key: Data, iv: Data) throws {
    if iv.count != algorithm.blockSize {
      throw CCError.paramError
    }
    ref =
      try key.withUnsafeBytes { keyPtr in
        try iv.withUnsafeBytes { ivPtr in
          var ref = CCCryptorRef(bitPattern: 0)
          let status = CCCryptorCreate(operation.rawValue, algorithm.rawValue, options.rawValue,
                                       keyPtr.baseAddress!, keyPtr.count, ivPtr.baseAddress, &ref)
          guard let value = ref, status == kCCSuccess else {
            throw CCError(rawValue: status)
          }
          return value
        }
      }
    blockSize = algorithm.blockSize
  }

  deinit {
    CCCryptorRelease(ref)
  }

  public func reset(iv: Data) throws {
    if iv.count != blockSize {
      throw CCError.paramError
    }
    try iv.withUnsafeBytes { ptr in
      let status = CCCryptorReset(ref, ptr.baseAddress)
      guard status == kCCSuccess else {
        throw CCError(rawValue: status)
      }
    }
  }

  public func updateLength(forInput length: Int) -> Int {
    return CCCryptorGetOutputLength(ref, length, false)
  }

  public func totalLength(forInput length: Int) -> Int {
    return CCCryptorGetOutputLength(ref, length, true)
  }

  public func update(data in: Data) throws -> Data {
    var out = Data(repeating: 0, count: updateLength(forInput: `in`.count))
    let moved = try update(data: `in`, into: &out)
    return out.prefix(upTo: moved)
  }

  public func update(data in: Data, into out: inout Data) throws -> Int {
    try `in`.withUnsafeBytes { inPtr in
      try out.withUnsafeMutableBytes { outPtr in
        try update(in: inPtr, out: outPtr)
      }
    }
  }

  public func update(in: UnsafeRawBufferPointer, out: UnsafeMutableRawBufferPointer) throws -> Int {
    return try update(in: `in`.baseAddress!, inLength: `in`.count, out: out.baseAddress!, outLength: out.count)
  }

  public func update(in: UnsafeRawPointer, inLength: Int, out: UnsafeMutableRawPointer, outLength: Int) throws -> Int {
    var moved = 0
    let status = CCCryptorUpdate(ref, `in`, inLength, out, outLength, &moved)
    guard status == kCCSuccess else {
      throw CCError(rawValue: status)
    }
    return moved
  }

  public func final() throws -> Data {
    var out = Data(repeating: 0, count: blockSize)
    let moved = try final(into: &out)
    return out.prefix(upTo: moved)
  }

  public func final(into out: inout Data) throws -> Int {
    try out.withUnsafeMutableBytes { outPtr in
      try final(out: outPtr)
    }
  }

  public func final(out: UnsafeMutableRawBufferPointer) throws -> Int {
    try final(out: out.baseAddress!, outLength: out.count)
  }

  public func final(out: UnsafeMutableRawPointer, outLength: Int) throws -> Int {
    var moved = 0
    let status = CCCryptorFinal(ref, out, outLength, &moved)
    guard status == kCCSuccess else {
      throw CCError(rawValue: status)
    }
    return moved
  }

  public func process(data: Data) throws -> Data {
    var result = Data(repeating: 0, count: totalLength(forInput: data.count))
    try result.withUnsafeMutableBytes { resultPtr in
      try data.withUnsafeBytes { dataPtr in
        var moved = try update(in: dataPtr, out: resultPtr)
        moved += try final(out: resultPtr.baseAddress!.advanced(by: moved), outLength: resultPtr.count - moved)
        assert(moved == resultPtr.count)
      }
    }
    return result
  }

  public static func crypt(_ data: Data, operation: Operation, using algorithm: Algorithm, options: Options,
                           key: Data, iv: Data) throws -> Data {
    var result = Data(repeating: 0, count: data.count + algorithm.blockSize)
    let moved =
      try result.withUnsafeMutableBytes { resultPtr -> Int in
        try data.withUnsafeBytes { dataPtr -> Int in
          try key.withUnsafeBytes { keyPtr -> Int in
            try iv.withUnsafeBytes { ivPtr -> Int in
              var moved = 0
              let status = CCCrypt(operation.rawValue, algorithm.rawValue, options.rawValue,
                                   keyPtr.baseAddress!, keyPtr.count, ivPtr.baseAddress!,
                                   dataPtr.baseAddress!, dataPtr.count,
                                   resultPtr.baseAddress!, resultPtr.count, &moved)
              guard status == kCCSuccess else {
                throw CCError(rawValue: status)
              }
              return moved
            }
          }
        }
      }
    return result.prefix(upTo: moved)
  }

  public static func encrypt(data: Data, using algorithm: Algorithm, options: Options,
                             key: Data, iv: Data) throws -> Data {
    return try crypt(data, operation: .encrypt, using: algorithm, options: options, key: key, iv: iv)
  }

  public static func decrypt(data: Data, using algorithm: Algorithm, options: Options,
                             key: Data, iv: Data) throws -> Data {
    return try crypt(data, operation: .decrypt, using: algorithm, options: options, key: key, iv: iv)
  }

}
