//
//  SecIdentity.swift
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
import ShieldX500
import ShieldX509



public extension SecIdentity {

  enum Error: Int, Swift.Error {
    case loadFailed
    case saveFailed
    case copyPrivateKeyFailed
    case copyCertificateFailed
  }

  static func create(certificate: SecCertificate, keyPair: SecKeyPair) throws -> SecIdentity {

    return try create(certificate: certificate, privateKey: keyPair.privateKey)
  }

  static func create(certificate: SecCertificate, privateKey: SecKey) throws -> SecIdentity {

    do {
      try privateKey.save()
    }
    catch SecKey.Error.saveDuplicate {
      // Allowable...
    }
    catch {
      throw Error.saveFailed
    }

    let query: [String: Any] = [
      kSecClass as String: kSecClassCertificate,
      kSecAttrLabel as String: UUID().uuidString,
      kSecValueRef as String: certificate,
    ]

    var data: CFTypeRef?

    let status = SecItemAdd(query as CFDictionary, &data)

    if status != errSecSuccess {
      try? privateKey.delete()
      throw Error.saveFailed
    }

    return try load(certificate: certificate)
  }


  static func load(certificate: SecCertificate) throws -> SecIdentity {

    let attrs = try certificate.attributes()

    let query: [String: Any] = [
      kSecClass as String: kSecClassIdentity,
      kSecAttrLabel as String: attrs[kSecAttrLabel as String]!,
      kSecReturnRef as String: kCFBooleanTrue!,
    ]

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    guard status == errSecSuccess, let result = result else {
      throw Error.loadFailed
    }

    return result as! SecIdentity // swiftlint:disable:this force_cast
  }

  func privateKey() throws -> SecKey {

    var key: SecKey?
    let status = SecIdentityCopyPrivateKey(self, &key)
    guard status == errSecSuccess, let key = key else {
      throw Error.copyPrivateKeyFailed
    }

    return key
  }

  func certificate() throws -> SecCertificate {

    var certificate: SecCertificate?
    let status = SecIdentityCopyCertificate(self, &certificate)
    guard status == errSecSuccess, let certificate = certificate else {
      throw Error.copyCertificateFailed
    }
    return certificate
  }

}
