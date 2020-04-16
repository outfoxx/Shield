//
//  SecKeyPair.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
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

  public enum Error: Swift.Error {
    case generateFailed
    case noMatchingKey
    case itemAddFailed
    case itemDeleteFailed
  }


  public class Builder {

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

    public func generate(applicationTag: Data) throws -> SecKeyPair {
      guard let type = type else { fatalError("missing key type") }
      guard let keySize = keySize else { fatalError("missing key size") }

      let privateAttrs: [String: Any] = [
         kSecAttrApplicationTag as String: applicationTag
      ]
      let attrs: [String: Any] = [
        kSecAttrKeyType as String: type.systemValue,
        kSecAttrKeySizeInBits as String: keySize,
        kSecPrivateKeyAttrs as String : privateAttrs as CFDictionary
      ]

      var publicKey: SecKey?, privateKey: SecKey?
      let status = SecKeyGeneratePair(attrs as CFDictionary, &publicKey, &privateKey)
      if status != errSecSuccess {
        throw SecKeyPair.Error.generateFailed
      }

      #if os(iOS) || os(watchOS) || os(tvOS)

        try publicKey!.save(class: kSecAttrKeyClassPublic)
        try privateKey!.save(class: kSecAttrKeyClassPrivate,applicationTag: applicationTag)

      #endif

      return SecKeyPair(privateKey: privateKey!, publicKey: publicKey!)
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

    privateKey = try SecKey.decode(fromData: privateKeyData,
                                   type: type.systemValue,
                                   class: kSecAttrKeyClassPrivate)

    // Assemble public key from private key
    let privateKey = try ASN1Decoder.decode(RSAPrivateKey.self, from: privateKeyData)
    let publicKeyData =
      try ASN1Encoder.encode(RSAPublicKey(modulus: privateKey.modulus, publicExponent: privateKey.publicExponent))

    publicKey = try SecKey.decode(fromData: publicKeyData,
                                  type: type.systemValue,
                                  class: kSecAttrKeyClassPublic)
  }

  public func save(applicationTag: Data) throws {

    try privateKey.save(class: kSecAttrKeyClassPrivate,applicationTag: applicationTag)
    try publicKey.save(class: kSecAttrKeyClassPublic)
  }

  public func delete() throws {

    try publicKey.delete()
    try privateKey.delete()
  }

  public func persistentReferences() throws -> (Data, Data) {
    return (try privateKey.persistentReference(), try publicKey.persistentReference())
  }

  public func encodedPublicKey() throws -> Data {
    return try publicKey.encode(class: kSecAttrKeyClassPublic) as Data
  }

  public func encodedPrivateKey() throws -> Data {
    return try privateKey.encode(class: kSecAttrKeyClassPrivate) as Data
  }

  public func matchesCertificate(certificate: SecCertificate, trustedCertificates: [SecCertificate]) throws -> Bool {

    let keyData =
      try certificate.publicKeyValidated(trustedCertificates: trustedCertificates).encode(class: kSecAttrKeyClassPublic)

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

    let keyType: SecKeyType
    let exportKeyLength: UInt64
    let exportKeyRounds: UInt64
    let exportKeySalt: Data
    let keyMaterial: Data
  }

  public func export(password: String,
                     derivedKeyLength: Int = exportDerivedKeyLengthDefault,
                     keyDerivationTiming: TimeInterval = exportKeyDerivationTimingDefault) throws -> Data {

    let passwordData = password.data(using: String.Encoding.utf8)!

    let exportKeySalt = try Random.generate(count: derivedKeyLength)

    let exportKeyRounds =
      try PBKDF.calibrate(passwordLength: passwordData.count, saltLength: exportKeySalt.count,
                          keyLength: derivedKeyLength, using: .pbkdf2, psuedoRandomAlgorithm: .sha512,
                          taking: keyDerivationTiming)

    let exportKey = try PBKDF.derive(length: derivedKeyLength, from: passwordData, salt: exportKeySalt,
                                     using: .pbkdf2, psuedoRandomAlgorithm: .sha512, rounds: exportKeyRounds)

    let keyMaterial = try encodedPrivateKey()
    let encryptedKeyMaterial = try Cryptor.encrypt(data: keyMaterial, using: .aes, options: [.pkcs7Padding],
                                                   key: exportKey, iv: exportKeySalt)

    let keyType = try privateKey.keyType(class: kSecAttrKeyClassPrivate)

    return try ASN1Encoder.encode(ExportedKey(keyType: keyType,
                                              exportKeyLength: UInt64(derivedKeyLength),
                                              exportKeyRounds: UInt64(exportKeyRounds),
                                              exportKeySalt: exportKeySalt,
                                              keyMaterial: encryptedKeyMaterial))
  }

  public static func `import`(fromData data: Data, withPassword password: String) throws -> SecKeyPair {

    let info = try ASN1Decoder.decode(ExportedKey.self, from: data)

    let exportKey = try PBKDF.derive(length: Int(info.exportKeyLength),
                                     from: password.data(using: .utf8)!, salt: info.exportKeySalt,
                                     using: .pbkdf2, psuedoRandomAlgorithm: .sha512, rounds: Int(info.exportKeyRounds))

    let keyMaterial = try Cryptor.decrypt(data: info.keyMaterial, using: .aes, options: .pkcs7Padding,
                                          key: exportKey, iv: info.exportKeySalt)

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
    privateKey = try SecKey.load(persistentReference: container.decode(Data.self, forKey: .private))
    publicKey = try SecKey.load(persistentReference: container.decode(Data.self, forKey: .public))
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: Self.CodingKeys.self)
    try container.encode(privateKey.persistentReference(), forKey: .private)
    try container.encode(publicKey.persistentReference(), forKey: .public)
  }

}
