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


/// Public and private key of an asymmetric key pair.
///
public struct SecKeyPair {

  /// Default final key length for PBKDF generated export keys.
  ///
  /// ## See Also
  /// - ``export(password:derivedKeyLength:keyDerivationTiming:)``
  ///
  public static let exportDerivedKeyLengthDefault = 32

  /// Default PBKDF generation time for generated export keys.
  ///
  /// ## See Also
  /// - ``export(password:derivedKeyLength:keyDerivationTiming:)``
  ///
  public static let exportKeyDerivationTimingDefault = TimeInterval(0.5)

  public enum Error: Int, Swift.Error {
    case generateFailed
    case failedToCopyPublicKeyFromPrivateKey

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


  /// Builder for ``SecKeyPair`` instances.
  ///
  /// Builders are used to generate multiple sets of key pairs.
  /// ```swift
  /// let builder = SecKeyPair.Builder().type(.ec).keySize(256)
  ///
  /// let keyPair1 = builder.generate("Encryption (Device 1)")
  /// let keyPair2 = builder.generate("Encryption (Device 2)")
  /// ```
  ///
  public class Builder {

    /// Key pair generation flags.
    public enum Flag {
      /// Generate the key pair in the secure enclave.
      case secureEnclave
    }

    /// Type of key pair to generate ``SecKeyType/ec`` or ``SecKeyType/rsa``.
    public let type: SecKeyType?
    /// Bit size of key pair to generate.
    public let keySize: Int?

    /// Initialize with a ``type`` and ``keySize``.
    ///
    public init(type: SecKeyType? = nil, keySize: Int? = nil) {
      self.type = type
      self.keySize = keySize
    }

    /// Set the type of key pair to be generated.
    ///
    public func type(_ type: SecKeyType) -> Builder {
      return Builder(type: type, keySize: keySize)
    }

    /// Set the bit size of the key pair to be generated.
    ///
    public func keySize(_ keySize: Int) -> Builder {
      return Builder(type: type, keySize: keySize)
    }

    /// Generates a key pair according the builder's `type` and `keySize`.
    ///
    /// The generated public and private key are "permanent" in the `Keychain`
    /// and can optionally be labeled with a user-visible label.
    ///
    /// - Parameters:
    ///   - label: User-visible label of the keys (optional).
    ///   - flat: Flags controlling the generation of the key pair.
    /// - Returns: Generated key pair.
    /// - Throws: Errors are thrown when the key generation of persistence to the kaychain fails.
    ///
    public func generate(label: String? = nil, flags: Set<Flag> = []) throws -> SecKeyPair {
      guard let type = type else { fatalError("missing key type") }
      guard let keySize = keySize else { fatalError("missing key size") }

      var attrs: [CFString: Any] = [
        kSecAttrKeyType: type.systemValue,
        kSecAttrKeySizeInBits: keySize,
        kSecAttrIsPermanent: true,
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

  /// Private key of the asymmetric key pair
  public let privateKey: SecKey
  /// Public key of the asymmetric key pair
  public let publicKey: SecKey

  /// Initialize with an explicit public and private key
  ///
  /// - Note: No checking is done to ensure the keys are part
  /// of the same asymmetric key pair.
  ///
  /// - Parameters:
  ///   - privateKey: Private key of the asymmetric key pair
  ///   - publicKey: Public key of the asymmetric key pair
  ///
  public init(privateKey: SecKey, publicKey: SecKey) {
    self.privateKey = privateKey
    self.publicKey = publicKey
  }

  /// Initialize with an explicit public and private key persistent keychain references.
  ///
  /// - Note: No checking is done to ensure the keys are part
  /// of the same asymmetric key pair.
  ///
  /// - Parameters:
  ///   - privateKey: Persistent keychain reference to the private key of the asymmetric key pair
  ///   - publicKey: Persistent keychain reference to the public key of the asymmetric key pair
  ///
  public init(privateKeyRef: Data, publicKeyRef: Data) throws {

    let privateKey = try SecKey.load(persistentReference: privateKeyRef)
    let publicKey = try SecKey.load(persistentReference: publicKeyRef)

    self.init(privateKey: privateKey, publicKey: publicKey)
  }

  /// Initialize key pair from the encoded external representation of the private key and its type.
  ///
  /// The encoded private key data must be in PKCS#1 for RSA keys and
  /// ASN1 X9.63 format for EC keys. This is the same format returned
  /// from `SecKeyCopyExternalRepresentation`.
  ///
  /// - Parameters:
  ///   - type: Type of private key (e.g. EC or RSA)
  ///   - privateKeyData: Encoded private key data.
  /// - Throws: An error is thrown if the private key is in the incorrect format or the
  /// public key cannot be retrieved from the keychain or derived from the private key.
  ///
  public init(type: SecKeyType, privateKeyData: Data) throws {

    privateKey = try SecKey.decode(
      fromData: privateKeyData,
      type: type.systemValue,
      class: kSecAttrKeyClassPrivate
    )

    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
      throw Error.failedToCopyPublicKeyFromPrivateKey
    }

    self.publicKey = publicKey
  }

  /// Save the public and private key to the `Keychain`.
  ///
  /// - Throws: Errors are thrown if either of the keys could not be saved.
  ///
  public func save() throws {

    try privateKey.save()
    try publicKey.save()
  }

  /// Delete the public and private key from the `Keychain`.
  ///
  /// - Throws: Errors are thrown if either of the keys could not be deleted.
  ///
  public func delete() throws {

    try publicKey.delete()
    try privateKey.delete()

  }

  /// Generate persistent keychain references for the public and private keys.
  ///
  /// - Returns: Tuple of the format (private key reference, public key reference).
  /// - Throws: Errors are thrown if a persistence reference cannot be generated for either of the keys.
  ///
  public func persistentReferences() throws -> (Data, Data) {
    return (try privateKey.persistentReference(), try publicKey.persistentReference())
  }

  /// Encode the public key into an external representation.
  ///
  /// The format is PKCS#1 for RSA keys and X9.63 for EC keys.
  ///
  public func encodedPublicKey() throws -> Data {
    return try publicKey.encode() as Data
  }

  /// Encode the private key into an external representation.
  ///
  /// The format is PKCS#1 for RSA keys and X9.63 for EC keys.
  ///
  public func encodedPrivateKey() throws -> Data {
    return try privateKey.encode() as Data
  }

  /// Check if the public key of the key pair matches the public key in a certificate.
  ///
  /// The certificate is first validated as a trusted certificate and then the key pair
  /// is checked against the public key of the key pair.
  ///
  /// - Parameters:
  ///   - certificate: Certificate to check for equality with the key pair's public key.
  ///   - trustedCertificates: Any certificates needed to complete the "chain-of-trust" for `certificate`.
  /// - Returns: True if the public key of `certificate` and the key pair match.
  ///
  public func matchesCertificate(certificate: SecCertificate, trustedCertificates: [SecCertificate]) throws -> Bool {

    let keyData =
      try certificate.publicKeyValidated(trustedCertificates: trustedCertificates).encode()

    return try encodedPublicKey() == keyData
  }

#if swift(>=5.5)
  /// Check if the public key of the key pair matches the public key in a certificate.
  ///
  /// The certificate is first validated as a trusted certificate and then the key pair
  /// is checked against the public key of the key pair.
  ///
  /// - Parameters:
  ///   - certificate: Certificate to check for equality with the key pair's public key.
  ///   - trustedCertificates: Any certificates needed to complete the "chain-of-trust" for `certificate`.
  /// - Returns: True if the public key of `certificate` and the key pair match.
  ///
  public func matchesCertificate(
    certificate: SecCertificate,
    trustedCertificates: [SecCertificate]
  ) async throws -> Bool {

    let keyData =
      try await certificate.publicKeyValidated(trustedCertificates: trustedCertificates).encode()

    return try encodedPublicKey() == keyData
  }
#endif


  /// Structure representing keys exported using ``export(password:derivedKeyLength:keyDerivationTiming:)``.
  ///
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

  /// Encrypt and encode the key pair's private key using PBKDF.
  ///
  /// Encrypt the key pair's private key with a password using PBKDF and then encode
  /// the encrypted key, along with the PBKDF parameters, into an ASN.1 structure.
  ///
  /// With the exported key and original password, ``import(fromData:withPassword:)``
  /// can be used to recover the original `SecKey`.
  ///
  /// - Parameters:
  ///   - password: Password use for key encryption.
  ///   - derivedKeyLength: PBKDF target key length.
  ///   - keyDerivationTiming: Time PBKDF function should take to generate encryption key.
  /// - Returns: Encoded encrypted key and PBKDF paraemters.
  ///
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

  /// Decode and decrypt a previously exported private key.
  ///
  /// Decodes the encrypted key and PBKDF paraameters from the provided ASN.1 data and then decrypts
  /// the private key. This is the reverse operation of ``export(password:derivedKeyLength:keyDerivationTiming:)``.
  ///
  /// - Parameters:
  ///   - data: Data for exported private key.
  ///   - password: Password used during key export.
  /// - Returns: ``SecKeyPair`` for the decoded/decrypted private.
  ///
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
