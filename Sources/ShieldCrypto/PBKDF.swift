//
//  PBKDF.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import CommonCrypto.CommonKeyDerivation
import Foundation


public enum PBKDF {

  public enum Error: Swift.Error {
    case calibrationFailed
  }

  public struct Algorithm: Equatable, Hashable, CaseIterable, CustomStringConvertible {
    public let rawValue: CCPBKDFAlgorithm
    public let name: String

    public init(rawValue: CCPBKDFAlgorithm, name: String) {
      self.rawValue = rawValue
      self.name = name
    }

    public static let pbkdf2 = Algorithm(rawValue: UInt32(kCCPBKDF2), name: "PBKDF2")

    public static let allCases: [Algorithm] = [.pbkdf2]

    public var description: String {
      return name
    }
  }

  public struct PsuedoRandomAlgorithm: Equatable, Hashable, CaseIterable, CustomStringConvertible {
    public let rawValue: CCPseudoRandomAlgorithm
    public let name: String

    public init(rawValue: CCPBKDFAlgorithm, name: String) {
      self.rawValue = rawValue
      self.name = name
    }

    @available(*, deprecated, message: "Use hmacSha1")
    public static let sha1 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA1), name: "SHA1")
    public static let hmacSha1 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA1), name: "SHA1")
    @available(*, deprecated, message: "Use hmacSha224")
    public static let sha224 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA224), name: "SHA224")
    public static let hmacSha224 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA224), name: "SHA224")
    @available(*, deprecated, message: "Use hmacSha256")
    public static let sha256 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA256), name: "SHA256")
    public static let hmacSha256 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA256), name: "SHA256")
    @available(*, deprecated, message: "Use hmacSha384")
    public static let sha384 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA384), name: "SHA384")
    public static let hmacSha384 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA384), name: "SHA384")
    @available(*, deprecated, message: "Use hmacSha512")
    public static let sha512 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA512), name: "SHA512")
    public static let hmacSha512 = PsuedoRandomAlgorithm(rawValue: UInt32(kCCPRFHmacAlgSHA512), name: "SHA512")

    public static let allCases: [PsuedoRandomAlgorithm] = [.hmacSha1, .hmacSha224, .hmacSha256, .hmacSha384, .hmacSha512]

    public var description: String {
      return name
    }
  }

  public static func derive(
    length keyLength: Int,
    from password: Data,
    salt: Data,
    using algorithm: Algorithm,
    psuedoRandomAlgorithm: PsuedoRandomAlgorithm,
    rounds: Int
  ) throws -> Data {

    var key = Data(repeating: 0, count: keyLength)
    try key.withUnsafeMutableBytes { keyPtr in
      try password.withUnsafeBytes { passwordPtr in
        try salt.withUnsafeBytes { saltPtr in
          let status = CCKeyDerivationPBKDF(
            algorithm.rawValue,
            passwordPtr.bindMemory(to: Int8.self).baseAddress,
            passwordPtr.count,
            saltPtr.bindMemory(to: UInt8.self).baseAddress!,
            saltPtr.count,
            psuedoRandomAlgorithm.rawValue,
            UInt32(rounds),
            keyPtr.bindMemory(to: UInt8.self).baseAddress!,
            keyPtr.count
          )
          if status != kCCSuccess {
            throw CCError(rawValue: status)
          }
        }
      }
    }

    return key
  }

  public static func calibrate(
    passwordLength: Int,
    saltLength: Int,
    keyLength: Int,
    using algorithm: Algorithm = .pbkdf2,
    psuedoRandomAlgorithm: PsuedoRandomAlgorithm = .hmacSha512,
    taking: TimeInterval
  ) throws -> Int {
    let rounds = CCCalibratePBKDF(
      algorithm.rawValue,
      passwordLength,
      saltLength,
      psuedoRandomAlgorithm.rawValue,
      keyLength,
      UInt32(taking * 1000)
    )
    if rounds == UInt32.max {
      throw Error.calibrationFailed
    }
    return Int(rounds)
  }

}
