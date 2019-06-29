//
//  SecKey.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import ShieldCrypto


public enum SecKeyError: Int, Error {

  case queryFailed
  case decryptionFailed
  case encryptionFailed
  case signFailed
  case verifyFailed
  case importFailed
  case exportFailed
  case saveFailed
  case saveDuplicate
  case deleteFailed

  public static func build(error: SecKeyError, message: String, status: OSStatus) -> NSError {
    let error = error as NSError
    return NSError(domain: error.domain, code: error.code, userInfo: [NSLocalizedDescriptionKey: message, "status": Int(status) as NSNumber])
  }

  public var status: OSStatus? {
    return (self as NSError).userInfo["status"] as? OSStatus
  }

}


public enum SecEncryptionPadding {
  case pkcs1
  case oaep
  case none
}


public extension SecKey {

  func persistentReference() throws -> Data {

    let query: [String: Any] = [
      kSecValueRef as String: self,
      kSecReturnPersistentRef as String: kCFBooleanTrue!,
    ]

    var ref: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &ref)
    if status != errSecSuccess {
      throw SecKeyError.build(error: .queryFailed, message: "Unable to locate transient reference", status: status)
    }
    return ref as! Data
  }

  static func load(persistentReference pref: Data) throws -> SecKey {

    let query: [String: Any] = [
      kSecValuePersistentRef as String: pref,
      kSecReturnRef as String: kCFBooleanTrue!,
    ]

    var ref: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &ref)
    if status != errSecSuccess {
      throw SecKeyError.build(error: .queryFailed, message: "Unable to locate persistent reference", status: status)
    }
    return ref as! SecKey
  }

  static func decode(fromData data: Data, type: CFString, class keyClass: CFString) throws -> SecKey {

    #if os(iOS) || os(watchOS) || os(tvOS)

      if #available(iOS 10, watchOS 3.3, *) {

        let attrs = [
          kSecClass as String: kSecClassKey,
          kSecAttrKeyClass as String: keyClass,
          kSecAttrKeyType as String: type,
        ] as CFDictionary

        var error: Unmanaged<CFError>?

        guard let key = SecKeyCreateWithData(data as CFData, attrs, &error), error == nil else {
          throw error!.takeRetainedValue()
        }

        return key
      }

      let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyClass as String: keyClass,
        kSecAttrKeyType as String: Int(type as String)! as CFNumber,
        kSecAttrApplicationTag as String: try Random.generateBytes(ofSize: 32),
        kSecReturnRef as String: kCFBooleanTrue!,
        kSecReturnPersistentRef as String: kCFBooleanTrue!,
        kSecValueData as String: data,
      ]

    #elseif os(macOS)

      if #available(macOS 10.12, *) {

        let attrs: [String: Any] = [
          kSecClass as String: kSecClassKey,
          kSecAttrKeyClass as String: keyClass,
          kSecAttrKeyType as String: type,
        ]

        var error: Unmanaged<CFError>?

        guard let key = SecKeyCreateWithData(data as CFData, attrs as CFDictionary, &error), error == nil else {
          throw error!.takeRetainedValue()
        }

        return key
      }


      let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyType as String: Int(type as String)! as CFNumber,
        kSecAttrApplicationTag as String: try Random.generate(count: 32),
        kSecReturnRef as String: kCFBooleanTrue!,
        kSecReturnPersistentRef as String: kCFBooleanTrue!,
        kSecValueData as String: data,
      ]

    #endif

    var result: CFTypeRef?

    let status = SecItemAdd(query as CFDictionary, &result)
    if status != errSecSuccess || result == nil {
      throw SecKeyError.build(error: .importFailed, message: "Unable to add key", status: status)
    }

    let results = result as! [String: Any]

    let key = results[kSecValueRef as String] as! SecKey
    let ref = results[kSecValuePersistentRef as String] as! Data

    try SecKey.delete(persistentReference: ref)

    return key
  }

  func encode(class keyClass: CFString) throws -> Data {

    #if os(iOS) || os(watchOS) || os(tvOS)

      if #available(iOS 10, watchOS 3.3, *) {

        var error: Unmanaged<CFError>?

        guard let data = SecKeyCopyExternalRepresentation(self, &error) else {
          throw error!.takeRetainedValue()
        }

        return data as Data
      }

      let query = [
        kSecClass as String: kSecClassKey,
        kSecAttrKeyClass as String: keyClass,
        kSecReturnData as String: kCFBooleanTrue!,
        kSecReturnPersistentRef as String: kCFBooleanTrue!,
        kSecValueRef as String: self,
      ] as CFDictionary

      var result: CFTypeRef?

      // Add temporary key, returning the encoded data
      let addStatus = SecItemAdd(query, &result)
      if addStatus != errSecSuccess {
        throw SecKeyError.build(error: .exportFailed, message: "Add failed", status: addStatus)
      }

      let results = result as! [String: Any]

      let data = results[kSecValueData as String] as! Data
      let ref = results[kSecValuePersistentRef as String] as! Data

      // Remove temporary key
      try SecKey.delete(persistentReference: ref)

    #elseif os(macOS)

      if #available(macOS 10.12, *) {

        var error: Unmanaged<CFError>?

        guard let data = SecKeyCopyExternalRepresentation(self, &error) else {
          throw error!.takeRetainedValue()
        }

        return data as Data
      }

      var result: CFData?

      let status = SecItemExport(self, SecExternalFormat.formatOpenSSL, [], nil, &result)
      if result == nil || status != errSecSuccess {
        throw SecKeyError.build(error: .exportFailed, message: "Export failed", status: status)
      }

      let data = result! as Data

    #endif

    return data
  }

  func attributes(class keyClass: CFString) throws -> [String: Any] {

    #if os(iOS) || os(watchOS) || os(tvOS)

      if #available(iOS 10, watchOS 3.3, *) {

        return SecKeyCopyAttributes(self) as! [String: Any]

      }
      else {

        let query = [
          kSecClass as String: kSecClassKey as Any,
          kSecAttrKeyClass as String: keyClass,
          kSecReturnAttributes as String: kCFBooleanTrue!,
          kSecReturnPersistentRef as String: kCFBooleanTrue!,
          kSecValueRef as String: self,
        ] as CFDictionary

        var result: CFTypeRef?

        // Add temporary key, returning the encoded data
        let addStatus = SecItemAdd(query, &result)
        if addStatus != errSecSuccess {
          throw SecKeyError.build(error: .queryFailed, message: "Add failed", status: addStatus)
        }

        let data = result as! [String: Any]

        let ref = data[kSecValuePersistentRef as String] as! Data

        // Remove the temporary key
        try SecKey.delete(persistentReference: ref)

        return data
      }

    #elseif os(macOS)

      if #available(macOS 10.12, *) {

        return SecKeyCopyAttributes(self) as! [String: Any]
      }
      else {

        let query: [String: Any] = [
          kSecReturnAttributes as String: kCFBooleanTrue!,
          kSecUseItemList as String: [self] as CFArray,
        ]

        var data: AnyObject?

        let status = SecItemCopyMatching(query as CFDictionary, &data)
        if status != errSecSuccess {
          throw SecKeyError.build(error: .queryFailed, message: "Unable to copy attributes", status: status)
        }

        return data as! [String: Any]
      }

    #endif

  }

  func type(class keyClass: CFString) throws -> CFString {

    let attrs = try attributes(class: keyClass)

    return (attrs[kSecAttrKeyType as String] as! NSNumber).stringValue as CFString
  }

  func save(class keyClass: CFString) throws {

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyClass as String: keyClass,
      kSecValueRef as String: self,
    ]

    let status = SecItemAdd(query as CFDictionary, nil)

    if status == errSecDuplicateItem {
      throw SecKeyError.saveDuplicate
    }
    else if status != errSecSuccess {
      throw SecKeyError.build(error: .saveFailed, message: "Item add failed", status: status)
    }

  }

  func delete() throws {

    try SecKey.delete(persistentReference: try persistentReference())
  }

  static func delete(persistentReference ref: Data) throws {

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecValuePersistentRef as String: ref,
    ]

    let status = SecItemDelete(query as CFDictionary)
    if status != errSecSuccess {
      throw SecKeyError.deleteFailed
    }
  }

  func encrypt(plainText: Data, padding: SecEncryptionPadding) throws -> Data {

    #if os(iOS) || os(watchOS) || os(tvOS)

      var cipherText = Data(count: SecKeyGetBlockSize(self))
      var cipherTextLen = cipherText.count
      let status =
        plainText.withUnsafeBytes { plainTextPtr in
          cipherText.withUnsafeMutableBytes { cipherTextPtr in
            SecKeyEncrypt(self,
                          padding == .oaep ? .OAEP : .PKCS1,
                          plainTextPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                          plainTextPtr.count,
                          cipherTextPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                          &cipherTextLen)
          }
        }

      if status != errSecSuccess {
        throw SecKeyError.build(error: .encryptionFailed, message: "Encryption failed", status: status)
      }

      return cipherText.subdata(in: 0 ..< cipherTextLen)

    #elseif os(macOS)

      // To ensure compatibility with iOS version above
      if plainText.count > SecKeyGetBlockSize(self) {
        throw SecKeyError.encryptionFailed
      }

      var error: Unmanaged<CFError>?

      let transform = SecEncryptTransformCreate(self, &error)
      if error != nil {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecPaddingKey, padding == .oaep ? kSecPaddingOAEPKey : kSecPaddingPKCS1Key, &error) {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecTransformInputAttributeName, plainText as CFData, &error) {
        throw error!.takeRetainedValue()
      }

      let cipherText: CFTypeRef? = SecTransformExecute(transform, &error)
      if cipherText == nil {
        throw error!.takeRetainedValue()
      }

      return cipherText as! Data

    #endif
  }

  func decrypt(cipherText: Data, padding: SecEncryptionPadding) throws -> Data {

    #if os(iOS) || os(watchOS) || os(tvOS)

      var plainText = Data(count: SecKeyGetBlockSize(self))
      var plainTextLen = plainText.count
      let status =
        cipherText.withUnsafeBytes { cipherTextPtr in
          plainText.withUnsafeMutableBytes { plainTextPtr in
            SecKeyDecrypt(self,
                          padding == .OAEP ? .OAEP : .PKCS1,
                          cipherTextPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                          cipherTextPtr.count,
                          plainTextPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                          &plainTextLen)
          }
        }

      if status != errSecSuccess {
        throw SecKeyError.build(error: .decryptionFailed, message: "Decryption failed", status: status)
      }
      return plainText.subdata(in: 0 ..< plainTextLen)

    #elseif os(macOS)

      var error: Unmanaged<CFError>?

      let transform = SecDecryptTransformCreate(self, &error)
      if error != nil {
        throw error!.takeRetainedValue()
      }

      let secPadding: CFString
      switch padding {
      case .oaep:
        secPadding = kSecPaddingOAEPKey
      case .pkcs1:
        secPadding = kSecPaddingPKCS1Key
      case .none:
        secPadding = kSecPaddingNoneKey
      }

      if !SecTransformSetAttribute(transform, kSecPaddingKey, secPadding, &error) {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecTransformInputAttributeName, cipherText as CFData, &error) {
        throw error!.takeRetainedValue()
      }

      let plainText: CFTypeRef? = SecTransformExecute(transform, &error)
      if plainText == nil {
        throw error!.takeRetainedValue()
      }

      return plainText as! Data

    #endif
  }

  #if os(iOS) || os(watchOS) || os(tvOS)
    private static func paddingOf(digestAlgorithm: DigestAlgorithm) -> SecPadding {

      switch digestAlgorithm {
      case .SHA1:
        return .PKCS1SHA1
      case .SHA224:
        return .PKCS1SHA224
      case .SHA256:
        return .PKCS1SHA256
      case .SHA384:
        return .PKCS1SHA384
      case .SHA512:
        return .PKCS1SHA512
      @unknown default:
        fatalError("unsupported digest algorithm")
      }
    }
  #endif

  func sign(data: Data, digestAlgorithm: Digester.Algorithm) throws -> Data {

    let digest = Digester.digest(data, using: digestAlgorithm)

    return try signHash(digest: digest, digestAlgorithm: digestAlgorithm)
  }

  func signHash(digest: Data, digestAlgorithm: Digester.Algorithm) throws -> Data {

    #if os(iOS) || os(watchOS) || os(tvOS)

      var signature = Data(count: SecKeyGetBlockSize(self))
      var signatureLen: Int = signature.count
      let status =
        digest.withUnsafeBytes { digestPtr in
          signature.withUnsafeMutableBytes { signaturePtr in
            SecKeyRawSign(self,
                          SecKey.paddingOf(digestAlgorithm: digestAlgorithm),
                          digestPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                          digestPtr.count,
                          signaturePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                          &signatureLen)
          }
        }

      if status != errSecSuccess {
        throw SecKeyError.build(error: .signFailed, message: "Sign failed", status: status)
      }

      return signature.subdata(in: 0 ..< signatureLen)

    #elseif os(macOS)

      var error: Unmanaged<CFError>?

      guard let transform = SecSignTransformCreate(self, &error) else {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecInputIsAttributeName, kSecInputIsDigest, &error) {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS1Key, &error) {
        throw error!.takeRetainedValue()
      }

      let digestType: CFString

      switch digestAlgorithm {
      case .sha1:
        digestType = kSecDigestSHA1

      case .sha224:
        digestType = kSecDigestSHA2

      case .sha256:
        digestType = kSecDigestSHA2

      case .sha384:
        digestType = kSecDigestSHA2

      case .sha512:
        digestType = kSecDigestSHA2

      default:
        fatalError("unsupported digest algorithm")
      }

      if !SecTransformSetAttribute(transform, kSecDigestTypeAttribute, digestType, &error) {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecDigestLengthAttribute, digestAlgorithm.hashBitLength as CFNumber, &error) {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecTransformInputAttributeName, digest as CFData, &error) {
        throw error!.takeRetainedValue()
      }

      let digest: CFTypeRef? = SecTransformExecute(transform, &error)
      if digest == nil {
        throw error!.takeRetainedValue()
      }

      return digest as! Data

    #endif
  }

  func verify(data: Data, againstSignature signature: Data, digestAlgorithm: Digester.Algorithm) throws -> Bool {

    let digest = Digester.digest(data, using: digestAlgorithm)

    return try verifyHash(digest: digest, againstSignature: signature, digestAlgorithm: digestAlgorithm)
  }

  func verifyHash(digest: Data, againstSignature signature: Data, digestAlgorithm: Digester.Algorithm) throws -> Bool {

    #if os(iOS) || os(watchOS) || os(tvOS)

      let status =
        digest.withUnsafeBytes { digestPtr in
          signature.withUnsafeBytes { signaturePtr in
            SecKeyRawVerify(self,
                            SecKey.paddingOf(digestAlgorithm: digestAlgorithm),
                            digestPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            digestPtr.count,
                            signaturePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            signature.count)
          }
        }

      switch status {
      case errSecSuccess:
        return true
      case errSSLCrypto:
        return false
      default:
        throw SecKeyError.build(error: .verifyFailed, message: "Verify failed", status: status)
      }

    #elseif os(macOS)


      var error: Unmanaged<CFError>?

      guard let transform = SecVerifyTransformCreate(self, signature as CFData, &error) else {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecInputIsAttributeName, kSecInputIsDigest, &error) {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecPaddingKey, kSecPaddingPKCS1Key, &error) {
        throw error!.takeRetainedValue()
      }

      let digestType: CFString

      switch digestAlgorithm {
      case .sha1:
        digestType = kSecDigestSHA1

      case .sha224:
        digestType = kSecDigestSHA2

      case .sha256:
        digestType = kSecDigestSHA2

      case .sha384:
        digestType = kSecDigestSHA2

      case .sha512:
        digestType = kSecDigestSHA2

      default:
        fatalError("unsupported digest algorithm")
      }

      if !SecTransformSetAttribute(transform, kSecDigestTypeAttribute, digestType, &error) {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecDigestLengthAttribute, digestAlgorithm.hashBitLength as CFNumber, &error) {
        throw error!.takeRetainedValue()
      }

      if !SecTransformSetAttribute(transform, kSecTransformInputAttributeName, digest as CFData, &error) {
        throw error!.takeRetainedValue()
      }

      let result: CFTypeRef? = SecTransformExecute(transform, &error)
      if result == nil {
        throw error!.takeRetainedValue()
      }

      return (result as! CFBoolean) == kCFBooleanTrue

    #endif
  }

}
