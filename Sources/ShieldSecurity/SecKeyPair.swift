//
//  SecKeyPair.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import Security
import ShieldCrypto
import ShieldPKCS
import PotentASN1


public enum SecKeyPairError: Error {
  case generateFailed
  case noMatchingKey
  case itemAddFailed
  case itemDeleteFailed

  public static func build(error: SecKeyPairError, message: String, status: OSStatus) -> NSError {
    let error = error as NSError
    return NSError(domain: error.domain, code: error.code, userInfo: [
      NSLocalizedDescriptionKey: message,
      "status": Int(status) as NSNumber,
    ])
  }
}


public enum SecKeyType: UInt32, CaseIterable, Codable {

  case RSA
  case EC

  var systemValue: CFString {
    switch self {
    case .RSA:
      return kSecAttrKeyTypeRSA
    case .EC:
      return kSecAttrKeyTypeEC
    }
  }
}


private let keyExportKeyLength = 32
private let keyExportTiming = TimeInterval(0.5)


public class SecKeyPairFactory {

  public let type: SecKeyType
  public let keySize: Int

  public init(type: SecKeyType, keySize: Int) {
    self.type = type
    self.keySize = keySize
  }

  public func generate() throws -> SecKeyPair {

    let attrs: [String: Any] = [
      kSecAttrKeyType as String: type.systemValue,
      kSecAttrKeySizeInBits as String: keySize,
    ]

    var publicKey: SecKey?, privateKey: SecKey?
    let status = SecKeyGeneratePair(attrs as CFDictionary, &publicKey, &privateKey)
    if status != errSecSuccess {
      throw SecKeyPairError.build(error: .generateFailed, message: "Generate failed", status: status)
    }

    #if os(iOS) || os(watchOS) || os(tvOS)

      try publicKey!.save(class: kSecAttrKeyClassPublic)
      try privateKey!.save(class: kSecAttrKeyClassPrivate)

    #endif

    return SecKeyPair(privateKey: privateKey!, publicKey: publicKey!)
  }

}


public class SecKeyPair: Codable {

  public let privateKey: SecKey
  public let publicKey: SecKey

  public init(privateKey: SecKey, publicKey: SecKey) {
    self.privateKey = privateKey
    self.publicKey = publicKey
  }

  public convenience init(privateKeyRef: Data, publicKeyRef: Data) throws {

    let privateKey = try SecKey.load(persistentReference: privateKeyRef)
    let publicKey = try SecKey.load(persistentReference: publicKeyRef)

    self.init(privateKey: privateKey, publicKey: publicKey)
  }

  public func save() throws {

    try privateKey.save(class: kSecAttrKeyClassPrivate)
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

  public struct ExportedKey: Codable {

    static let asn1Schema: Schema =
      .sequence([
        "keyType": .integer(),
        "exportKeyLength": .integer(),
        "exportKeyRounds": .integer(),
        "exportKeySalt": .octetString(),
        "keyMaterial": .octetString()
      ])

    let keyType: SecKeyType
    let exportKeyLength: UInt64
    let exportKeyRounds: UInt64
    let exportKeySalt: Data
    let keyMaterial: Data
  }

  public func export(password: String) throws -> Data {

    let passwordData = password.data(using: String.Encoding.utf8)!

    let exportKeySalt = try Random.generate(count: keyExportKeyLength)

    let exportKeyRounds =
      try PBKDF.calibrate(passwordLength: passwordData.count, saltLength: exportKeySalt.count, keyLength: keyExportKeyLength,
                          using: .pbkdf2, psuedoRandomAlgorithm: .sha512, taking: keyExportTiming)

    let exportKey = try PBKDF.derive(length: keyExportKeyLength, from: passwordData, salt: exportKeySalt,
                                     using: .pbkdf2, psuedoRandomAlgorithm: .sha512, rounds: exportKeyRounds)

    let keyMaterial = try encodedPrivateKey()
    let encryptedKeyMaterial = try Cryptor.encrypt(data: keyMaterial, using: .aes, options: [.pkcs7Padding],
                                                   key: exportKey, iv: exportKeySalt)

    let keyType: SecKeyType

    let attrs = try privateKey.attributes(class: kSecAttrKeyClassPrivate)

    // iOS 10 SecKeyCopyAttributes returns string values, SecItemCopyMatching returns number values
    let type =
      (attrs[kSecAttrKeyType as String] as? NSNumber)?.stringValue ??
      attrs[kSecAttrKeyType as String] as! String

    if type == kSecAttrKeyTypeRSA as String {
      keyType = .RSA
    }
    else if type == kSecAttrKeyTypeEC as String {
      keyType = .EC
    }
    else {
      fatalError("Unsupported key type")
    }

    return try ASN1Encoder(schema: ExportedKey.asn1Schema)
      .encode(ExportedKey(keyType: keyType,
                          exportKeyLength: UInt64(keyExportKeyLength),
                          exportKeyRounds: UInt64(exportKeyRounds),
                          exportKeySalt: exportKeySalt,
                          keyMaterial: encryptedKeyMaterial))
  }

  public static func importKeys(fromData data: Data, withPassword password: String) throws -> SecKeyPair {

    let info = try ASN1Decoder(schema: ExportedKey.asn1Schema).decode(ExportedKey.self, from: data)

    let exportKey = try PBKDF.derive(length: Int(info.exportKeyLength),
                                     from: password.data(using: .utf8)!, salt: info.exportKeySalt,
                                     using: .pbkdf2, psuedoRandomAlgorithm: .sha512, rounds: Int(info.exportKeyRounds))

    let keyMaterial = try Cryptor.decrypt(data: info.keyMaterial, using: .aes, options: .pkcs7Padding,
                                          key: exportKey, iv: info.exportKeySalt)

    let secPrivateKey = try SecKey.decode(fromData: keyMaterial,
                                          type: info.keyType.systemValue,
                                          class: kSecAttrKeyClassPrivate)

    // Assemble DER public key from private key material
    let privateKey = try ASN1Decoder(schema: Schemas.RSAPrivateKey).decode(RSAPrivateKey.self, from: keyMaterial)
    let publicKey = RSAPublicKey(modulus: privateKey.modulus, publicExponent: privateKey.publicExponent)
    let pubKeyMaterial = try ASN1Encoder(schema: Schemas.RSAPublicKey).encode(publicKey)

    let secPublicKey = try SecKey.decode(fromData: pubKeyMaterial,
                                         type: info.keyType.systemValue,
                                         class: kSecAttrKeyClassPublic)

    return SecKeyPair(privateKey: secPrivateKey, publicKey: secPublicKey)
  }

  public func matchesCertificate(certificate: SecCertificate, trustedCertificates: [SecCertificate]) throws -> Bool {

    let keyData = try certificate.publicKeyValidated(trustedCertificates: trustedCertificates).encode(class: kSecAttrKeyClassPublic)

    return try encodedPublicKey() == keyData
  }

  enum CodingKeys: CodingKey {
    case `public`
    case `private`
  }

  public required init(from decoder: Decoder) throws {
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
