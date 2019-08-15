//
//  HMAC.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import CommonCrypto.CommonHMAC
import Foundation


public struct HMAC {

  public struct Algorithm: Equatable, Hashable, CaseIterable, CustomStringConvertible {
    public let rawValue: CCHmacAlgorithm
    public let name: String

    public init(rawValue: CCHmacAlgorithm, name: String) {
      self.rawValue = rawValue
      self.name = name
    }

    public static let md5 = Algorithm(rawValue: UInt32(kCCHmacAlgMD5), name: "MD5")
    public static let sha1 = Algorithm(rawValue: UInt32(kCCHmacAlgSHA1), name: "SHA1")
    public static let sha224 = Algorithm(rawValue: UInt32(kCCHmacAlgSHA224), name: "SHA224")
    public static let sha256 = Algorithm(rawValue: UInt32(kCCHmacAlgSHA256), name: "SHA256")
    public static let sha384 = Algorithm(rawValue: UInt32(kCCHmacAlgSHA384), name: "SHA384")
    public static let sha512 = Algorithm(rawValue: UInt32(kCCHmacAlgSHA512), name: "SHA512")

    public static let allCases: [Algorithm] = [.md5, .sha1, .sha224, .sha256, .sha384, .sha512]

    public var hashByteLength: Int {
      switch self {
      case .md5: return Int(CC_MD5_DIGEST_LENGTH)
      case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
      case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
      case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
      case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
      case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
      default:
        fatalError("Unsupported hash algorithm for HMAC")
      }
    }

    public var description: String {
      return name
    }
  }

  private var algorithm: Algorithm
  private var context = CCHmacContext()

  public init(_ algorithm: Algorithm, key: Data) {
    self.algorithm = algorithm
    reset(key: key)
  }

  public mutating func reset(key: Data) {
    key.withUnsafeBytes { ptr in
      CCHmacInit(&self.context, algorithm.rawValue, ptr.baseAddress!, ptr.count)
    }
  }

  public mutating func update(data: Data) {
    data.withUnsafeBytes { ptr in
      update(data: ptr)
    }
  }

  public mutating func update(data: UnsafeRawBufferPointer) {
    update(data: data.baseAddress!, dataLength: data.count)
  }

  public mutating func update(data: UnsafeRawPointer, dataLength: Int) {
    CCHmacUpdate(&context, data, dataLength)
  }

  public mutating func final() -> Data {
    var hash = Data(repeating: 0, count: algorithm.hashByteLength)
    hash.withUnsafeMutableBytes { ptr in
      CCHmacFinal(&self.context, ptr.baseAddress!)
    }
    return hash
  }

  public static func hmac(_ data: Data, using algorithm: Algorithm, key: Data) -> Data {
    var hash = Data(repeating: 0, count: algorithm.hashByteLength)
    hash.withUnsafeMutableBytes { hashPtr in
      data.withUnsafeBytes { dataPtr in
        key.withUnsafeBytes { keyPtr in
          CCHmac(algorithm.rawValue, keyPtr.baseAddress!, keyPtr.count, dataPtr.baseAddress!, dataPtr.count, hashPtr.baseAddress!)
        }
      }
    }
    return hash
  }

}
