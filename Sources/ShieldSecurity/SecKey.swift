//
//  SecKey.swift
//  Shield
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
  case invalidOperation
  case noAttributes

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


private let maxSignatureBufferLen = 512


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

  func encode() throws -> Data {

    var error: Unmanaged<CFError>?
    
    guard let data = SecKeyCopyExternalRepresentation(self, &error) else {
      throw error!.takeRetainedValue()
    }
    
    return data as Data
  }

  func attributes() throws -> [String: Any] {
    
    guard let attrs = SecKeyCopyAttributes(self) as? [String: Any] else {
      throw SecKeyError.noAttributes
    }
    
    return attrs
  }

  func keyType() throws -> SecKeyType {
    
    let typeStr = try self.type() as CFString
    
    guard let type = SecKeyType(systemValue: typeStr) else {
      fatalError("Unsupported key type")
    }
    
    return type
  }

  func type() throws -> String {

    let attrs = try attributes()

    // iOS 10 SecKeyCopyAttributes returns string values, SecItemCopyMatching returns number values
    guard let type = (attrs[kSecAttrKeyType as String] as? NSNumber)?.stringValue ?? (attrs[kSecAttrKeyType as String] as? String) else {
      fatalError("Invalid key type")
    }
    
    return type
  }

  func save() throws {
    
    let attrs = try attributes()

    let query: [String: Any] = [
      kSecClass as String: kSecClassKey,
      kSecAttrKeyClass as String: attrs[kSecAttrKeyClass as String]!,
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

    guard try self.keyType() == .rsa else {
      throw SecKeyError.invalidOperation
    }
    
    let algorithm: SecKeyAlgorithm
    switch padding {
    case .pkcs1:
      algorithm = .rsaEncryptionPKCS1
    case .oaep:
      algorithm = .rsaEncryptionOAEPSHA1
    case .none:
      algorithm = .rsaEncryptionRaw
    }
    
    var error: Unmanaged<CFError>?
    
    guard let cipherText = SecKeyCreateEncryptedData(self, algorithm, plainText as CFData, &error) else {
      if let error = error {
        throw error.takeRetainedValue()
      } else {
        throw SecKeyError.decryptionFailed
      }
    }
    
    return cipherText as Data
  }

  func decrypt(cipherText: Data, padding: SecEncryptionPadding) throws -> Data {

    guard try self.keyType() == .rsa else {
      throw SecKeyError.invalidOperation
    }
    
    let algorithm: SecKeyAlgorithm
    switch padding {
    case .pkcs1:
      algorithm = .rsaEncryptionPKCS1
    case .oaep:
      algorithm = .rsaEncryptionOAEPSHA1
    case .none:
      algorithm = .rsaEncryptionRaw
    }
    
    var error: Unmanaged<CFError>?
    
    guard let plainText = SecKeyCreateDecryptedData(self, algorithm, cipherText as CFData, &error) else {
      if let error = error {
        throw error.takeRetainedValue()
      } else {
        throw SecKeyError.decryptionFailed
      }
    }
    
    return plainText as Data
  }

  func sign(data: Data, digestAlgorithm: Digester.Algorithm) throws -> Data {

    let digest = Digester.digest(data, using: digestAlgorithm)

    return try signHash(digest: digest, digestAlgorithm: digestAlgorithm)
  }

  func signHash(digest: Data, digestAlgorithm: Digester.Algorithm) throws -> Data {
      let digestType: SecKeyAlgorithm

      switch digestAlgorithm {
      case .sha1:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA1
        } else {
          digestType = .ecdsaSignatureDigestX962SHA1
        }

      case .sha224:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA224
        } else {
          digestType = .ecdsaSignatureDigestX962SHA224
        }

      case .sha256:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA256
        } else {
          digestType = .ecdsaSignatureDigestX962SHA256
        }

      case .sha384:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA384
        } else {
          digestType = .ecdsaSignatureDigestX962SHA384
        }

      case .sha512:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA512
        } else {
          digestType = .ecdsaSignatureDigestX962SHA512
        }

      default:
        fatalError("unsupported digest algorithm")
      }

      var error: Unmanaged<CFError>?

      guard let signature = SecKeyCreateSignature(self, digestType, digest as CFData, &error) else {
        throw error!.takeRetainedValue()
      }

      return signature as Data
  }

  func verify(data: Data, againstSignature signature: Data, digestAlgorithm: Digester.Algorithm) throws -> Bool {

    let digest = Digester.digest(data, using: digestAlgorithm)

    return try verifyHash(digest: digest, againstSignature: signature, digestAlgorithm: digestAlgorithm)
  }

  func verifyHash(digest: Data, againstSignature signature: Data, digestAlgorithm: Digester.Algorithm) throws -> Bool {
      let digestType: SecKeyAlgorithm

      switch digestAlgorithm {
      case .sha1:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA1
        } else {
          digestType = .ecdsaSignatureDigestX962SHA1
        }

      case .sha224:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA224
        } else {
          digestType = .ecdsaSignatureDigestX962SHA224
        }

      case .sha256:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA256
        } else {
          digestType = .ecdsaSignatureDigestX962SHA256
        }

      case .sha384:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA384
        } else {
          digestType = .ecdsaSignatureDigestX962SHA384
        }

      case .sha512:
        if try! self.keyType() == .rsa {
          digestType = .rsaSignatureDigestPKCS1v15SHA512
        } else {
          digestType = .ecdsaSignatureDigestX962SHA512
        }

      default:
        fatalError("unsupported digest algorithm")
      }

      var error: Unmanaged<CFError>? = nil

      return SecKeyVerifySignature(self, digestType, digest as CFData, signature as CFData, &error)
  }

}
