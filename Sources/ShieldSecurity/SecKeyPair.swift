//
//  SecKeyPair.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Algorithms
import CryptoKit
import Foundation
import PotentASN1
import Security
import ShieldCrypto
import ShieldOID
import ShieldX509


/// Public and private key of an asymmetric key pair.
///
public struct SecKeyPair {

  /// Default final key size for PBKDF generated export keys.
  ///
  /// ## See Also
  /// - ``export(password:derivedKeyLength:keyDerivationTiming:)``
  ///
  public static let exportDerivedKeySizeDefault: ExportKeySize = .bits256

  /// Default final psuedorandom algorthm for PBKDF generated export keys.
  ///
  /// ## See Also
  /// - ``export(password:derivedKeyLength:keyDerivationTiming:)``
  ///
  public static let exportPsuedoRandomAlgorithmDefault: PBKDF.PsuedoRandomAlgorithm = .hmacSha512

  /// Default PBKDF generation time for generated export keys.
  ///
  /// ## See Also
  /// - ``export(password:derivedKeyLength:keyDerivationTiming:)``
  ///
  public static let exportKeyDerivationTimingDefault = TimeInterval(0.5)

  public enum Error: Int, Swift.Error {
    case generateFailed
    case failedToCopyPublicKeyFromPrivateKey
    case invalidEncodedPrivateKey

    @available(*, deprecated, message: "Unused")
    case noMatchingKey
    @available(*, deprecated, message: "Unused")
    case itemAddFailed
    @available(*, deprecated, message: "Unused")
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
      /// Should the key be saved in the keychain automatically.
      case permanent
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
    ///   - flags: Flags controlling the generation of the key pair.
    ///   - accessibility: Accessibility of the generated key pair.
    /// - Returns: Generated key pair.
    /// - Throws: Errors are thrown when the key generation of persistence to the kaychain fails.
    ///
    public func generate(
      label: String? = nil,
      flags: Set<Flag> = [.permanent],
      accessibility: SecAccessibility = .default
    ) throws -> SecKeyPair {
      guard let type = type else { fatalError("missing key type") }
      guard let keySize = keySize else { fatalError("missing key size") }

      let isPermanent = flags.contains(.permanent) || flags.contains(.secureEnclave) || accessibility != .default

      var attrs: [String: Any] = [
        kSecAttrKeyType as String: type.systemValue,
        kSecAttrKeySizeInBits as String: keySize,
        kSecAttrIsPermanent as String: isPermanent,
        kSecUseDataProtectionKeychain as String: true,
        kSecAttrAccessible as String: accessibility.attr
      ]

      if let label = label {
        attrs[kSecAttrLabel as String] = label
      }

      if flags.contains(.secureEnclave) {
        attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
      }

      var error: Unmanaged<CFError>?

      guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
        throw error?.takeRetainedValue() ?? SecKeyPair.Error.generateFailed
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
      data: privateKeyData,
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
  public func save(accessibility: SecAccessibility = .default) throws {

    try privateKey.save(accessibility: accessibility)
    try publicKey.save(accessibility: accessibility)
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
  public func matchesCertificate(certificate: SecCertificate, trustedCertificates: [SecCertificate]) -> Bool {

    do {

      let keyData = try certificate.publicKeyValidated(trustedCertificates: trustedCertificates).encode()

      return try encodedPublicKey() == keyData
    }
    catch {
      return false
    }
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
  ) async -> Bool {

    do {

      let keyData = try await certificate.publicKeyValidated(trustedCertificates: trustedCertificates).encode()

      return try encodedPublicKey() == keyData
    }
    catch {
      return false
    }
  }
#endif

  public enum ExportKeySize: Int {
    case bits128 = 16
    case bits192 = 24
    case bits256 = 32
  }

  /// Encodes the key pair's private key in PKCS#8 format and then encrypts it using PBKDF and packages
  /// into PKCS#8 encrypted format.
  ///
  /// With the exported key and original password, ``import(data:password:)``
  /// can be used to recover the original `SecKey`.
  ///
  /// - Parameters:
  ///   - password: Password use for key encryption.
  ///   - derivedKeySize: PBKDF target key size.
  ///   - psuedoRandomAlgorithm: Which psuedo random algorithm should be used with PBKDF.
  ///   - keyDerivationTiming: Time PBKDF function should take to generate encryption key.
  /// - Returns: Encrypted PKCS#8 encoded private key.
  ///
  public func export(
    password: String,
    derivedKeySize: ExportKeySize = exportDerivedKeySizeDefault,
    psuedoRandomAlgorithm: PBKDF.PsuedoRandomAlgorithm = exportPsuedoRandomAlgorithmDefault,
    keyDerivationTiming: TimeInterval = exportKeyDerivationTimingDefault
  ) throws -> Data {

    // Derive key from password

    let passwordData = password.data(using: String.Encoding.utf8)!

    let exportKeySalt = try Random.generate(count: derivedKeySize.rawValue)

    let exportKeyRounds =
      try PBKDF.calibrate(
        passwordLength: passwordData.count,
        saltLength: exportKeySalt.count,
        keyLength: derivedKeySize.rawValue,
        using: .pbkdf2,
        psuedoRandomAlgorithm: psuedoRandomAlgorithm,
        taking: keyDerivationTiming
      )

    let exportKey = try PBKDF.derive(
      length: derivedKeySize.rawValue,
      from: passwordData,
      salt: exportKeySalt,
      using: .pbkdf2,
      psuedoRandomAlgorithm: psuedoRandomAlgorithm,
      rounds: exportKeyRounds
    )

    // Encode and encrypt PKCS#8 PrivateKeyInfo

    let encodedPrivateKey = try privateKey.encodePKCS8()

    let encryptedPrivateKeyIV = try Random.generate(count: 16)

    let encryptedPrivateKey = try Cryptor.crypt(encodedPrivateKey,
                                                operation: .encrypt,
                                                using: .aes,
                                                options: .pkcs7Padding,
                                                key: exportKey,
                                                iv: encryptedPrivateKeyIV)

    // Build PKCS#8 EncryptedPrivateKeyInfo

    let encryptedPrivateKeyInfo =
      try EncryptedPrivateKeyInfo.build(encryptedData: encryptedPrivateKey,
                                        pbkdf2Salt: exportKeySalt,
                                        pbkdf2IterationCount: UInt64(exportKeyRounds),
                                        pbkdf2KeyLength: UInt64(derivedKeySize.rawValue),
                                        pbkdf2Prf: psuedoRandomAlgorithm.prfAlgorithm.oid,
                                        aesEncryptionScheme: derivedKeySize.aesCBCAlgorithm.oid,
                                        aesIV: encryptedPrivateKeyIV)

    let encryptedPrivateKeyInfoData = try ASN1Encoder.encode(encryptedPrivateKeyInfo)

    return encryptedPrivateKeyInfoData
  }

  /// Encodes the key pair's private key in PKCS#8 format.
  ///
  /// With the exported key and original password, ``import(data:password:)``
  /// can be used to recover the original `SecKey`.
  ///
  /// - Returns: Encoded encrypted key and PBKDF paraemters.
  ///
  public func export() throws -> Data {

    return try privateKey.encodePKCS8()
  }

  /// Decrypts an encrypted PKCS#8 encrypted private key and builds a complete key pair.
  ///
  /// This is the reverse operation of ``export(password:derivedKeyLength:keyDerivationTiming:)``.
  ///
  /// - Note: Only supports PKCS#8's PBES2 sceheme using PBKDF2 for key derivation.
  ///
  /// - Parameters:
  ///   - data: Data for exported private key.
  ///   - password: Password used during key export.
  /// - Returns: ``SecKeyPair`` for the decrypted & decoded private key.
  ///
  @available(*, deprecated, message: "Use import(data:password:) instead")
  public static func `import`(fromData data: Data, withPassword password: String) throws -> SecKeyPair {
    return try self.import(data: data, password: password)
  }

  /// Decrypts an encrypted PKCS#8 encrypted private key and builds a complete key pair.
  ///
  /// This is the reverse operation of ``export(password:derivedKeyLength:keyDerivationTiming:)``.
  ///
  /// - Note: Only supports PKCS#8's PBES2 sceheme using PBKDF2 for key derivation.
  ///
  /// - Parameters:
  ///   - data: Data for exported private key.
  ///   - password: Password used during key export.
  /// - Returns: ``SecKeyPair`` for the decrypted & decoded private key.
  ///
  public static func `import`(data: Data, password: String) throws -> SecKeyPair {

    typealias Nist = iso_itu.country.us.organization.gov.csor.nistAlgorithms
    typealias RSADSI = iso.memberBody.us.rsadsi
    typealias PKCS = RSADSI.pkcs
    let supportedEncOids = [Nist.aes.aes128_CBC_PAD.oid, Nist.aes.aes192_CBC_PAD.oid, Nist.aes.aes256_CBC_PAD.oid]

    let info = try ASN1.Decoder.decode(EncryptedPrivateKeyInfo.self, from: data)

    // Convert and validate requirements (PBKDF2 and AES-CBC-PAD encryption)

    guard
      info.encryptionAlgorithm.algorithm == RSADSI.pkcs.pkcs5.pbes2.oid,
      let encAlgParams = try? info.encryptionAlgorithm.parameters.map({ try ASN1.Decoder.decodeTree(PBES2Params.self, from: $0) }),
      encAlgParams.keyDerivationFunc.algorithm == PKCS.pkcs5.pbkdf2.oid,
      let pbkdf2Params = try? encAlgParams.keyDerivationFunc.parameters.map({ try ASN1.Decoder.decodeTree(PBKDF2Params.self, from: $0) }),
      supportedEncOids.contains(encAlgParams.encryptionScheme.algorithm),
      let aesIV = encAlgParams.encryptionScheme.parameters?.octetStringValue
    else {
      throw Error.invalidEncodedPrivateKey
    }

    // Derive import key from password and PBKDF2 params in encrypted PKCS#8 data

    let importKey = try PBKDF.derive(
      length: Int(pbkdf2Params.keyLength),
      from: password.data(using: .utf8)!,
      salt: pbkdf2Params.salt,
      using: .pbkdf2,
      psuedoRandomAlgorithm: try PBKDF.PsuedoRandomAlgorithm.from(oid: pbkdf2Params.prf.algorithm),
      rounds: Int(pbkdf2Params.iterationCount)
    )

    // Decrypt & decode PKCS#8 PrivateKeyInfo

    let privateKeyInfoData = try Cryptor.crypt(info.encryptedData,
                                               operation: .decrypt,
                                               using: .aes,
                                               options: .pkcs7Padding,
                                               key: importKey,
                                               iv: aesIV)

    return try Self.import(data: privateKeyInfoData)
  }

  /// Decodes a PKCS#8 encoded private key and builds a complete key pair.
  ///
  /// - Parameters:
  ///   - data: Data for exported private key.
  /// - Returns: ``SecKeyPair`` for the decrypted private key.
  ///
  @available(*, deprecated, message: "Use import(data:) instead")
  public static func `import`(fromData data: Data) throws -> SecKeyPair {
    return try self.import(data: data)
  }

  /// Decodes a PKCS#8 encoded private key and builds a complete key pair.
  ///
  /// - Parameters:
  ///   - data: Data for exported private key.
  /// - Returns: ``SecKeyPair`` for the decrypted private key.
  ///
  public static func `import`(data: Data) throws -> SecKeyPair {

    let privateKeyInfo: PrivateKeyInfo
    do {
      privateKeyInfo = try ASN1.Decoder.decode(PrivateKeyInfo.self, from: data)
    }
    catch {
      throw SecKeyPair.Error.invalidEncodedPrivateKey
    }

    // Convert to SecKey decode params

    let (keyType, keyDecodeData) = try SecKey.extractDecodeParams(privateKeyInfo: privateKeyInfo)

    return try Self(type: keyType, privateKeyData: keyDecodeData)
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

private extension SecKey {

  static func extractDecodeParams(privateKeyInfo: PrivateKeyInfo) throws -> (SecKeyType, Data) {

    let keyType: SecKeyType
    let importKeyData: Data
    switch privateKeyInfo.privateKeyAlgorithm.algorithm {
    case iso.memberBody.us.rsadsi.pkcs.pkcs1.rsaEncryption.oid:
      keyType = .rsa
      importKeyData = privateKeyInfo.privateKey

    case iso.memberBody.us.ansix962.keyType.ecPublicKey.oid:
      keyType = .ec

      let ecPrivateKey = try ASN1.Decoder.decode(ECPrivateKey.self, from: privateKeyInfo.privateKey)
      guard
        let curveOID = privateKeyInfo.privateKeyAlgorithm.parameters?.objectIdentifierValue
      else {
        throw SecKey.Error.importFailed
      }

      switch curveOID {
      case iso.memberBody.us.ansix962.curves.prime.prime256v1.oid:
        importKeyData = try P256.Signing.PrivateKey(rawRepresentation: ecPrivateKey.privateKey).x963Representation
      case iso.org.certicom.curve.ansip384r1.oid:
        importKeyData = try P384.Signing.PrivateKey(rawRepresentation: ecPrivateKey.privateKey).x963Representation
      case iso.org.certicom.curve.ansip521r1.oid:
        importKeyData = try P521.Signing.PrivateKey(rawRepresentation: ecPrivateKey.privateKey).x963Representation
      default:
        throw AlgorithmIdentifier.Error.unsupportedAlgorithm
      }

    default:
      throw AlgorithmIdentifier.Error.unsupportedAlgorithm
    }

    return (keyType, importKeyData)
  }

  func encodePKCS8() throws -> Data {
    let privateKeyInfo: PrivateKeyInfo
    switch try keyType() {
    case .rsa:
      privateKeyInfo = try generateRSAPrivateKeyInfo()

    case .ec:
      privateKeyInfo = try generateECPrivateKeyInfo()
    }

    return try ASN1.Encoder.encode(privateKeyInfo)
  }

  private func generateRSAPrivateKeyInfo() throws -> PrivateKeyInfo {
    let encodedPrivateKey = try encode()

    return PrivateKeyInfo(privateKeyAlgorithm: .init(algorithm: iso.memberBody.us.rsadsi.pkcs.pkcs1.rsaEncryption.oid),
                          privateKey: encodedPrivateKey)
  }

  private func generateECPrivateKeyInfo() throws -> PrivateKeyInfo {
    let encodedPrivateKey = try encode()

    let (curveOID, keyNumberSize) = try getECCurveAndNumberSize()

    let parts = encodedPrivateKey.dropFirst().chunks(ofCount: keyNumberSize)
    if parts.count != 3 {
      throw SecKeyPair.Error.invalidEncodedPrivateKey
    }

    let encodedPublicKey = Data(encodedPrivateKey.prefix(1) + parts.dropLast().joined())

    let privateKey = ECPrivateKey(version: .one,
                                  privateKey: parts.last!,
                                  parameters: curveOID,
                                  publicKey: BitString(bytes: encodedPublicKey))

    let privateKeyData = try ASN1.Encoder.encode(privateKey)

    return PrivateKeyInfo(version: .zero,
                          privateKeyAlgorithm: .init(algorithm: iso.memberBody.us.ansix962.keyType.ecPublicKey.oid,
                                                     parameters: ASN1.objectIdentifier(curveOID.fields)),
                          privateKey: privateKeyData)
  }

  func getECCurveAndNumberSize() throws -> (OID, Int) {

    switch try keyAttributes()[kSecAttrKeySizeInBits as String] as? Int ?? 0 {
    case 192:
      // P-192, secp192r1
      return (iso.memberBody.us.ansix962.curves.prime.prime192v1.oid, 24)
    case 256:
      // P-256, secp256r1
      return (iso.memberBody.us.ansix962.curves.prime.prime256v1.oid, 32)
    case 384:
      // P-384, secp384r1
      return (iso.org.certicom.curve.ansip384r1.oid, 48)
    case 521:
      // P-521, secp521r1
      return (iso.org.certicom.curve.ansip521r1.oid, 66)
    default:
      throw AlgorithmIdentifier.Error.unsupportedAlgorithm
    }
  }

}

private extension PBKDF.PsuedoRandomAlgorithm {

  var prfAlgorithm: iso.memberBody.us.rsadsi.digestAlgorithm {
    typealias Algs = iso.memberBody.us.rsadsi.digestAlgorithm

    switch self {
    case .hmacSha1:
      return Algs.hmacWithSHA1
    case .hmacSha224:
      return Algs.hmacWithSHA224
    case .hmacSha256:
      return Algs.hmacWithSHA256
    case .hmacSha384:
      return Algs.hmacWithSHA384
    case .hmacSha512:
      return Algs.hmacWithSHA512
    default:
      fatalError("Unsupported PBKDF Psuedo Random Algorithm")
    }
  }

  static func from(oid: OID) throws -> Self {
    typealias Algs = iso.memberBody.us.rsadsi.digestAlgorithm

    switch oid {
    case Algs.hmacWithSHA1.oid:
      return .hmacSha1
    case Algs.hmacWithSHA224.oid:
      return .hmacSha224
    case Algs.hmacWithSHA256.oid:
      return .hmacSha256
    case Algs.hmacWithSHA384.oid:
      return .hmacSha384
    case Algs.hmacWithSHA512.oid:
      return .hmacSha512
    default:
      throw SecKeyPair.Error.invalidEncodedPrivateKey
    }
  }

}

private extension SecKeyPair.ExportKeySize {

  var aesCBCAlgorithm: iso_itu.country.us.organization.gov.csor.nistAlgorithms.aes {
    typealias AES = iso_itu.country.us.organization.gov.csor.nistAlgorithms.aes

    switch self {
    case .bits128:
      return AES.aes128_CBC_PAD
    case .bits192:
      return AES.aes192_CBC_PAD
    case .bits256:
      return AES.aes256_CBC_PAD
    }
  }

}

private extension EncryptedPrivateKeyInfo {

  static func build(
    encryptedData: Data,
    pbkdf2Salt: Data,
    pbkdf2IterationCount: UInt64,
    pbkdf2KeyLength: UInt64,
    pbkdf2Prf: OID,
    aesEncryptionScheme: OID,
    aesIV: Data
  ) throws -> EncryptedPrivateKeyInfo {
    typealias PKCS = iso.memberBody.us.rsadsi.pkcs.pkcs5

    let pbkdf2Params = PBKDF2Params(salt: pbkdf2Salt,
                                    iterationCount: pbkdf2IterationCount,
                                    keyLength: pbkdf2KeyLength,
                                    prf: .init(algorithm: pbkdf2Prf))

    let encAlgParams = PBES2Params(keyDerivationFunc: .init(algorithm: PKCS.pbkdf2.oid,
                                                            parameters: try ASN1.Encoder.encodeTree(pbkdf2Params)),
                                   encryptionScheme: .init(algorithm: aesEncryptionScheme,
                                                           parameters: .octetString(aesIV)))

    let encAlgId = AlgorithmIdentifier(algorithm: PKCS.pbes2.oid,
                                       parameters: try ASN1.Encoder.encodeTree(encAlgParams))

    return EncryptedPrivateKeyInfo(encryptionAlgorithm: encAlgId,
                                   encryptedData: encryptedData)
  }
}
