//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/11/19.
//

import Foundation
import CommonCrypto


public struct CCError: Swift.Error, RawRepresentable, Equatable, Hashable {
  public let rawValue: CCCryptorStatus

  public init(rawValue: CCCryptorStatus) {
    self.rawValue = rawValue
  }

  public static let paramError = CCError(rawValue: Int32(kCCParamError))
  public static let bufferTooSmall = CCError(rawValue: Int32(kCCBufferTooSmall))
  public static let memoryFailure = CCError(rawValue: Int32(kCCMemoryFailure))
  public static let alignmentError = CCError(rawValue: Int32(kCCAlignmentError))
  public static let decodeError = CCError(rawValue: Int32(kCCDecodeError))
  public static let unimplemented = CCError(rawValue: Int32(kCCUnimplemented))
  public static let overflow = CCError(rawValue: Int32(kCCOverflow))
  public static let rngFailure = CCError(rawValue: Int32(kCCRNGFailure))
  public static let unspecified = CCError(rawValue: Int32(kCCUnspecifiedError))
  public static let callSequenceError = CCError(rawValue: Int32(kCCCallSequenceError))
  public static let keySize = CCError(rawValue: Int32(kCCKeySizeError))
  public static let invalidKey = CCError(rawValue: Int32(kCCInvalidKey))
}
