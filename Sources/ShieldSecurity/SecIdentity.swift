//
//  SecIdentity.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import Security
import ShieldX500
import ShieldX509
import PotentASN1


public enum SecIdentityError: Int, Error {

  case loadFailed
  case saveFailed
  case copyPrivateKeyFailed
  case copyCertificateFailed

  public static func build(error: SecIdentityError, message: String, status: OSStatus? = nil, underlyingError: Error? = nil) -> NSError {

    let error = error as NSError

    var userInfo = [
      NSLocalizedDescriptionKey: message,
    ] as [String: Any]

    if let status = status {
      userInfo["status"] = Int(status) as NSNumber
    }

    if let underlyingError = underlyingError {
      userInfo[NSUnderlyingErrorKey] = underlyingError as NSError
    }

    return NSError(domain: error.domain, code: error.code, userInfo: userInfo)
  }

}


public extension SecIdentity {

  static func load(certificate: SecCertificate) throws -> SecIdentity {

    let attrs = try certificate.attributes()

    let query: [String: Any] = [
      kSecClass as String: kSecClassIdentity,
      kSecAttrLabel as String: attrs[kSecAttrLabel as String]!,
      kSecReturnRef as String: kCFBooleanTrue!,
    ]

    var result: CFTypeRef?

    let status = SecItemCopyMatching(query as CFDictionary, &result)

    if status != errSecSuccess || result == nil {
      throw SecIdentityError.loadFailed
    }

    return result as! SecIdentity
  }

  func privateKey() throws -> SecKey {

    var key: SecKey?
    let status = SecIdentityCopyPrivateKey(self, &key)
    if status != errSecSuccess {
      throw SecIdentityError.copyPrivateKeyFailed
    }

    return key!
  }

  func certificate() throws -> SecCertificate {

    var crt: SecCertificate?
    let status = SecIdentityCopyCertificate(self, &crt)
    if status != errSecSuccess {
      throw SecIdentityError.copyCertificateFailed
    }
    return crt!
  }

}


public class SecIdentityBuilder {

  public let certificateSigningRequest: CertificationRequest
  public let keyPair: SecKeyPair

  private init(certificateSigningRequest: CertificationRequest, keyPair: SecKeyPair) {
    self.certificateSigningRequest = certificateSigningRequest
    self.keyPair = keyPair
  }

  public static func generate(subject: Name, keySize: Int, usage: SecKeyUsage) throws -> SecIdentityBuilder {

    let keyPair = try SecKeyPairFactory(type: .RSA, keySize: keySize).generate()

    let certificateSigningRequest = try CertificationRequest.Builder()
      .subject(name: subject)
      .publicKey(keyPair: keyPair)
      .build(signingKey: keyPair.privateKey, digestAlgorithm: .sha256)

    return SecIdentityBuilder(certificateSigningRequest: certificateSigningRequest, keyPair: keyPair)
  }

  public func save(withCertificate certificate: SecCertificate) throws {

    do {
      try keyPair.save()
    }
    catch SecKeyError.saveDuplicate {
      // Allowable...
    }
    catch {
      throw SecIdentityError.build(error: .saveFailed, message: "Unable to save key pair")
    }

    let query: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: UUID().uuidString,
      kSecValueRef as String: certificate,
    ]

    var data: CFTypeRef?

    let status = SecItemAdd(query as CFDictionary, &data)

    if status != errSecSuccess {
      do { try keyPair.delete() } catch {}
      throw SecIdentityError.build(error: .saveFailed, message: "Unable to add certificate", status: status)
    }

  }

}
