//
//  Digest.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import CommonCrypto.CommonDigest
import Foundation


public protocol DigestContext {
  init()
}

extension CC_MD2_CTX: DigestContext {}
extension CC_MD4_CTX: DigestContext {}
extension CC_MD5_CTX: DigestContext {}
extension CC_SHA1_CTX: DigestContext {}
extension CC_SHA256_CTX: DigestContext {}
extension CC_SHA512_CTX: DigestContext {}


public protocol DigestEngine {

  associatedtype Context: DigestContext

  typealias Init = (UnsafeMutablePointer<Context>) -> Int32
  typealias Update = (UnsafeMutablePointer<Context>, UnsafeRawPointer, CC_LONG) -> Int32
  typealias Final = (UnsafeMutablePointer<UInt8>, UnsafeMutablePointer<Context>) -> Int32
  typealias Digest = (UnsafeRawPointer, CC_LONG, UnsafeMutablePointer<UInt8>) -> UnsafeMutablePointer<UInt8>?

  static var hashLength: Int32 { get }
  static var `init`: Init { get }
  static var update: Update { get }
  static var final: Final { get }
  static var digest: Digest { get }
}

public struct MD2Engine: DigestEngine {
  public typealias Context = CC_MD2_CTX
  public static let hashLength = CC_MD2_DIGEST_LENGTH
  public static let `init`: Init = CC_MD2_Init
  public static let update: Update = CC_MD2_Update
  public static let final: Final = CC_MD2_Final
  public static let digest: Digest = CC_MD2
}

public struct MD4Engine: DigestEngine {
  public typealias Context = CC_MD4_CTX
  public static let hashLength = CC_MD4_DIGEST_LENGTH
  public static let `init`: Init = CC_MD4_Init
  public static let update: Update = CC_MD4_Update
  public static let final: Final = CC_MD4_Final
  public static let digest: Digest = CC_MD4
}

public struct MD5Engine: DigestEngine {
  public typealias Context = CC_MD5_CTX
  public static let hashLength = CC_MD5_DIGEST_LENGTH
  public static let `init`: Init = CC_MD5_Init
  public static let update: Update = CC_MD5_Update
  public static let final: Final = CC_MD5_Final
  public static let digest: Digest = CC_MD5
}


public struct SHA1Engine: DigestEngine {
  public typealias Context = CC_SHA1_CTX
  public static let hashLength = CC_SHA1_DIGEST_LENGTH
  public static let `init`: Init = CC_SHA1_Init
  public static let update: Update = CC_SHA1_Update
  public static let final: Final = CC_SHA1_Final
  public static let digest: Digest = CC_SHA1
}

public struct SHA224Engine: DigestEngine {
  public typealias Context = CC_SHA256_CTX
  public static let hashLength = CC_SHA224_DIGEST_LENGTH
  public static let `init`: Init = CC_SHA224_Init
  public static let update: Update = CC_SHA224_Update
  public static let final: Final = CC_SHA224_Final
  public static let digest: Digest = CC_SHA224
}

public struct SHA256Engine: DigestEngine {
  public typealias Context = CC_SHA256_CTX
  public static let hashLength = CC_SHA256_DIGEST_LENGTH
  public static let `init`: Init = CC_SHA256_Init
  public static let update: Update = CC_SHA256_Update
  public static let final: Final = CC_SHA256_Final
  public static let digest: Digest = CC_SHA256
}

public struct SHA384Engine: DigestEngine {
  public typealias Context = CC_SHA512_CTX
  public static let hashLength = CC_SHA384_DIGEST_LENGTH
  public static let `init`: Init = CC_SHA384_Init
  public static let update: Update = CC_SHA384_Update
  public static let final: Final = CC_SHA384_Final
  public static let digest: Digest = CC_SHA384
}

public struct SHA512Engine: DigestEngine {
  public typealias Context = CC_SHA512_CTX
  public static let hashLength = CC_SHA512_DIGEST_LENGTH
  public static let `init`: Init = CC_SHA512_Init
  public static let update: Update = CC_SHA512_Update
  public static let final: Final = CC_SHA512_Final
  public static let digest: Digest = CC_SHA512
}


public protocol AnyDigester {

  static var hashLength: Int { get }

  mutating func update(data: Data)
  mutating func update(data: UnsafeRawBufferPointer)
  mutating func update(data: UnsafeRawPointer, dataLength: Int)

  mutating func final() -> Data

  static func digest(data: Data) -> Data
  static func digest(data: UnsafeRawBufferPointer) -> Data
  static func digest(data: UnsafeRawPointer, dataLength: Int) -> Data

  init()

}

public extension AnyDigester {

  mutating func update(data: Data) {
    data.withUnsafeBytes { ptr in
      update(data: ptr)
    }
  }

  mutating func update(data: UnsafeRawBufferPointer) {
    update(data: data.baseAddress!, dataLength: data.count)
  }

  static func digest(data: Data) -> Data {
    return data.withUnsafeBytes { dataPtr in
      digest(data: dataPtr)
    }
  }

  static func digest(data: UnsafeRawBufferPointer) -> Data {
    return digest(data: data.baseAddress!, dataLength: data.count)
  }

}


public struct Digester {

  public enum Algorithm {
    case md2
    case md4
    case md5
    case sha1
    case sha224
    case sha256
    case sha384
    case sha512

    public var hashByteLength: Int {
      return Digester.type(self).hashLength
    }

    public var hashBitLength: Int {
      return Digester.type(self).hashLength * 8
    }
  }

  public static func type(_ algorithm: Algorithm) -> AnyDigester.Type {
    switch algorithm {
    case .md2: return MD2Digester.self
    case .md4: return MD4Digester.self
    case .md5: return MD5Digester.self
    case .sha1: return SHA1Digester.self
    case .sha224: return SHA224Digester.self
    case .sha256: return SHA256Digester.self
    case .sha384: return SHA384Digester.self
    case .sha512: return SHA512Digester.self
    }
  }

  public static func `for`(_ algorithm: Algorithm) -> AnyDigester {
    return type(algorithm).init()
  }

  public static func digest(_ data: Data, using algorithm: Algorithm) -> Data {
    return type(algorithm).digest(data: data)
  }

}


public struct _Digester<Engine: DigestEngine>: AnyDigester {

  public static var hashLength: Int {
    return Int(Engine.hashLength)
  }

  private var context = Engine.Context()

  public init() {
    // swiftformat:disable:next redundantInit,redundantBackticks
    _ = Engine.`init`(&context)
  }

  public mutating func update(data: UnsafeRawPointer, dataLength: Int) {
    _ = Int(Engine.update(&context, data, UInt32(dataLength)))
  }

  public mutating func final() -> Data {
    var result = Data(repeating: 0, count: Int(Engine.hashLength))
    result.withUnsafeMutableBytes { ptr in
      _ = Engine.final(ptr.bindMemory(to: UInt8.self).baseAddress!, &context)
    }
    return result
  }

  public static func digest(data: UnsafeRawPointer, dataLength: Int) -> Data {
    var result = Data(repeating: 0, count: Int(Engine.hashLength))
    result.withUnsafeMutableBytes { resultPtr in
      _ = Engine.digest(data, CC_LONG(dataLength), resultPtr.bindMemory(to: UInt8.self).baseAddress!)
    }
    return result
  }

}


public typealias MD2Digester = _Digester<MD2Engine>
public typealias MD4Digester = _Digester<MD4Engine>
public typealias MD5Digester = _Digester<MD5Engine>

public typealias SHA1Digester = _Digester<SHA1Engine>
public typealias SHA224Digester = _Digester<SHA224Engine>
public typealias SHA256Digester = _Digester<SHA256Engine>
public typealias SHA384Digester = _Digester<SHA384Engine>
public typealias SHA512Digester = _Digester<SHA512Engine>
