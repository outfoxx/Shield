//
//  SecKeyPair.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import Security
import ShieldCrypto
import ShieldPKCS


public struct SecKeyPair {

  public static let exportDerivedKeyLengthDefault = 32
  public static let exportKeyDerivationTimingDefault = TimeInterval(0.5)

  public enum Error: Int, Swift.Error {
    case generateFailed
    case failedToCopyPublicKeyFromPrivateKey
    case noMatchingKey
    case itemAddFailed
    case itemDeleteFailed

    public static func build(error: Error, message: String, status: OSStatus) -> NSError {
      let error = error as NSError
      return NSError(
        domain: error.domain,
        code: error.code,
        userInfo: [NSLocalizedDescriptionKey: message, "status": Int(status) as NSNumber]
      )
    }

    public var status: OSStatus? {
      return (self as NSError).userInfo["status"] as? OSStatus
    }

  }


  public class Builder {

    public enum Flag {
      case secureEnclave
    }

    public let type: SecKeyType?
    public let keySize: Int?

    public init(type: SecKeyType? = nil, keySize: Int? = nil) {
      self.type = type
      self.keySize = keySize
    }

    public func type(_ type: SecKeyType) -> Builder {
      return Builder(type: type, keySize: keySize)
    }

    public func keySize(_ keySize: Int) -> Builder {
      return Builder(type: type, keySize: keySize)
    }

    public func generate(label: String? = nil, flags: Set<Flag> = []) throws -> SecKeyPair {
      guard let type = type else { fatalError("missing key type") }
      guard let keySize = keySize else { fatalError("missing key size") }

      var attrs: [CFString: Any] = [
        kSecAttrKeyType: type.systemValue,
        kSecAttrKeySizeInBits: keySize,
        kSecAttrIsPermanent : true
      ]

      if let label = label {
        attrs[kSecAttrLabel] = label
      }

      if flags.contains(.secureEnclave) {
        attrs[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
      }
        
      var error: Unmanaged<CFError>?
        
      guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
          throw SecKeyPair.Error.generateFailed
      }
      
      guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
          throw SecKeyPair.Error.failedToCopyPublicKeyFromPrivateKey
      }
      
      return SecKeyPair(privateKey: privateKey, publicKey: publicKey)
    }
  }


  public let privateKey: SecKey
  public let publicKey: SecKey

  public init(privateKey: SecKey, publicKey: SecKey) {
    self.privateKey = privateKey
    self.publicKey = publicKey
  }

  public init(privateKeyRef: Data, publicKeyRef: Data) throws {

    let privateKey = try SecKey.load(persistentReference: privateKeyRef)
    let publicKey = try SecKey.load(persistentReference: publicKeyRef)

    self.init(privateKey: privateKey, publicKey: publicKey)
  }

  public init(type: SecKeyType, privateKeyData: Data) throws {

    privateKey = try SecKey.decode(
      fromData: privateKeyData,
      type: type.systemValue,
      class: kSecAttrKeyClassPrivate
    )

    // Assemble public key from private key
    let privateKey = try ASN1Decoder.decode(RSAPrivateKey.self, from: privateKeyData)
    let publicKeyData =
      try ASN1Encoder.encode(RSAPublicKey(modulus: privateKey.modulus, publicExponent: privateKey.publicExponent))

    publicKey = try SecKey.decode(
      fromData: publicKeyData,
      type: type.systemValue,
      class: kSecAttrKeyClassPublic
    )
  }

  public func save() throws {

    try privateKey.save()
    try publicKey.save()
  }

  public func delete() throws {

    try publicKey.delete()
    try privateKey.delete()

  }

  public func persistentReferences() throws -> (Data, Data) {
    return (try privateKey.persistentReference(), try publicKey.persistentReference())
  }

  public func encodedPublicKey() throws -> Data {
    return try publicKey.encode() as Data
  }

  public func encodedPrivateKey() throws -> Data {
    return try privateKey.encode() as Data
  }

  public func matchesCertificate(certificate: SecCertificate, trustedCertificates: [SecCertificate]) throws -> Bool {

    let keyData =
      try certificate.publicKeyValidated(trustedCertificates: trustedCertificates).encode()

    return try encodedPublicKey() == keyData
  }

  public struct ExportedKey: Codable, SchemaSpecified {

    public static let asn1Schema: Schema =
      .sequence([
        "keyType": .integer(),
        "exportKeyLength": .integer(),
        "exportKeyRounds": .integer(),
        "exportKeySalt": .octetString(),
        "keyMaterial": .octetString(),
      ])

    public var keyType: SecKeyType
    public var exportKeyLength: UInt64
    public var exportKeyRounds: UInt64
    public var exportKeySalt: Data
    public var keyMaterial: Data
  }

  public func export(
    password: String,
    derivedKeyLength: Int = exportDerivedKeyLengthDefault,
    keyDerivationTiming: TimeInterval = exportKeyDerivationTimingDefault
  ) throws -> Data {

    let passwordData = password.data(using: String.Encoding.utf8)!

    let exportKeySalt = try Random.generate(count: derivedKeyLength)

    let exportKeyRounds =
      try PBKDF.calibrate(
        passwordLength: passwordData.count,
        saltLength: exportKeySalt.count,
        keyLength: derivedKeyLength,
        using: .pbkdf2,
        psuedoRandomAlgorithm: .sha512,
        taking: keyDerivationTiming
      )

    let exportKey = try PBKDF.derive(
      length: derivedKeyLength,
      from: passwordData,
      salt: exportKeySalt,
      using: .pbkdf2,
      psuedoRandomAlgorithm: .sha512,
      rounds: exportKeyRounds
    )

    let keyMaterial = try encodedPrivateKey()
    let encryptedKeyMaterial = try Cryptor.encrypt(
      data: keyMaterial,
      using: .aes,
      options: [.pkcs7Padding],
      key: exportKey,
      iv: exportKeySalt
    )

    let keyType = try privateKey.keyType()

    return try ASN1Encoder.encode(ExportedKey(
      keyType: keyType,
      exportKeyLength: UInt64(derivedKeyLength),
      exportKeyRounds: UInt64(exportKeyRounds),
      exportKeySalt: exportKeySalt,
      keyMaterial: encryptedKeyMaterial
    ))
  }

  public static func `import`(fromData data: Data, withPassword password: String) throws -> SecKeyPair {

    let info = try ASN1Decoder.decode(ExportedKey.self, from: data)

    let exportKey = try PBKDF.derive(
      length: Int(info.exportKeyLength),
      from: password.data(using: .utf8)!,
      salt: info.exportKeySalt,
      using: .pbkdf2,
      psuedoRandomAlgorithm: .sha512,
      rounds: Int(info.exportKeyRounds)
    )

    let keyMaterial = try Cryptor.decrypt(
      data: info.keyMaterial,
      using: .aes,
      options: .pkcs7Padding,
      key: exportKey,
      iv: info.exportKeySalt
    )

    return try Self(type: info.keyType, privateKeyData: keyMaterial)
  }

}


extension SecKeyPair: Codable {

  enum CodingKeys: CodingKey {
    case `public`
    case `private`
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: Self.CodingKeys.self)
    try self.init(privateKeyRef: container.decode(Data.self, forKey: .private),
                  publicKeyRef: container.decode(Data.self, forKey: .public))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: Self.CodingKeys.self)
    try container.encode(privateKey.persistentReference(), forKey: .private)
    try container.encode(publicKey.persistentReference(), forKey: .public)
  }

}
