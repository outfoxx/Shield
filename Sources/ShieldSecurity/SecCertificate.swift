//
//  SecCertificate.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import Regex
import Security
import ShieldCrypto
import ShieldOID
import ShieldPKCS
import ShieldX500
import ShieldX509


public enum SecCertificateError: Int, Error {
  case loadFailed = 0
  case saveFailed = 1
  case queryFailed = 2
  case trustCreationFailed = 3
  case trustValidationFailed = 4
  case trustValidationError = 5
  case publicKeyRetrievalFailed = 6
  case parsingFailed = 7
}


public extension SecCertificate {

  static func from(data: Data) throws -> SecCertificate {
    guard let cert = SecCertificateCreateWithData(nil, data as CFData) else {
      throw SecCertificateError.parsingFailed
    }
    return cert
  }

  private var certificateInfo: TBSCertificate? {
    return try? ASN1Decoder(schema: Schemas.TBSCertificate).decode(Certificate.self, from: derEncoded).tbsCertificate
  }

  var issuerName: Name? {
    if #available(iOS 10.3, OSX 10.12.4, tvOS 10.3, watchOS 3.3, *) {
      guard
        let issuerData = SecCertificateCopyNormalizedIssuerSequence(self),
        let issuer = try? ASN1Decoder(schema: Schemas.Name).decode(Name.self, from: issuerData as Data)
      else {
        fatalError("invalid certificate encoding")
      }
      return issuer
    }
    else {
      return certificateInfo?.issuer
    }
  }

  var subjectName: Name? {
    if #available(iOS 10.3, OSX 10.12.4, tvOS 10.3, watchOS 3.3, *) {
      guard
        let subjectData = SecCertificateCopyNormalizedSubjectSequence(self),
        let subject = try? ASN1Decoder(schema: Schemas.Name).decode(Name.self, from: subjectData as Data)
      else {
        fatalError("invalid certificate encoding")
      }
      return subject
    }
    else {
      return certificateInfo?.subject
    }
  }

  func publicKeyValidated(trustedCertificates: [SecCertificate]) throws -> SecKey {

    let policy = SecPolicyCreateBasicX509()

    var trustResult: SecTrust?
    var status = SecTrustCreateWithCertificates(self, policy, &trustResult)
    guard let trust = trustResult, status == errSecSuccess else {
      throw SecCertificateError.trustCreationFailed
    }

    status = SecTrustSetAnchorCertificates(trust, trustedCertificates as CFArray)
    if status != errSecSuccess {
      throw SecCertificateError.trustCreationFailed
    }

    var result = SecTrustResultType.deny

    status = SecTrustEvaluate(trust, &result)
    if status != errSecSuccess {
      throw SecCertificateError.trustValidationError
    }

    if
      result != SecTrustResultType.proceed,
      result != SecTrustResultType.unspecified {
      throw SecCertificateError.trustValidationFailed
    }

    guard let key = SecTrustCopyPublicKey(trust) else {
      throw SecCertificateError.publicKeyRetrievalFailed
    }

    return key
  }

  var derEncoded: Data {
    return SecCertificateCopyData(self) as Data
  }

  func attributes() throws -> [String: Any] {

    #if os(iOS) || os(watchOS) || os(tvOS)

      let query = [
        kSecReturnAttributes as String: kCFBooleanTrue!,
        kSecValueRef as String: self,
      ] as CFDictionary

      var data: CFTypeRef?

      let status = SecItemCopyMatching(query as CFDictionary, &data)
      if status != errSecSuccess {
        throw SecCertificateError.queryFailed
      }

    #elseif os(macOS)

      let query: [String: Any] = [
        kSecReturnAttributes as String: kCFBooleanTrue!,
        kSecUseItemList as String: [self] as CFArray,
      ]

      var data: AnyObject?

      let status = SecItemCopyMatching(query as CFDictionary, &data)
      if status != errSecSuccess {
        throw SecCertificateError.queryFailed
      }

    #endif

    return data as! [String: Any]
  }

  func save() throws {

    let query = [
      kSecClass as String: kSecClassCertificate,
      kSecValueRef as String: self,
    ] as CFDictionary

    var data: CFTypeRef?

    let status = SecItemAdd(query, &data)

    if status != errSecSuccess {
      throw SecCertificateError.saveFailed
    }
  }

  static func load(resourceName: String, inDirectory dir: String? = nil, in bundle: Bundle? = nil) throws -> [SecCertificate]? {

    let bundle = bundle ?? Bundle.main

    if let loaded = try load(derResourceName: resourceName, inDirectory: dir, in: bundle) {
      return [loaded]
    }

    if let loaded = try load(pemResourceName: resourceName, inDirectory: dir, in: bundle) {
      return loaded
    }

    return nil
  }

  static func load(derResourceName: String, inDirectory dir: String? = nil, in bundle: Bundle? = nil) throws -> SecCertificate? {

    let bundle = bundle ?? Bundle.main

    guard let certURL = bundle.url(forResource: derResourceName, withExtension: "crt", subdirectory: dir) else {
      return nil
    }

    guard let certData = try? Data(contentsOf: certURL) else {
      throw SecCertificateError.loadFailed
    }

    return try load(der: certData)
  }

  static func load(der: Data) throws -> SecCertificate {

    guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
      throw SecCertificateError.loadFailed
    }

    return cert
  }

  static func load(pemResourceName: String, inDirectory dir: String? = nil, in bundle: Bundle? = nil) throws -> [SecCertificate]? {

    let bundle = bundle ?? Bundle.main

    guard let certsURL = bundle.url(forResource: pemResourceName, withExtension: "pem", subdirectory: dir) else {
      return nil
    }

    guard
      let certsData = try? Data(contentsOf: certsURL),
      let certsPEM = String(data: certsData, encoding: .utf8)
    else {
      throw SecCertificateError.loadFailed
    }

    return try load(pem: certsPEM)
  }

  private static let pemRegex = Regex(#"-----BEGIN CERTIFICATE-----\s*([a-zA-Z0-9\s/+]+=*)\s*-----END CERTIFICATE-----"#)
  private static let pemWhitespaceRegex = Regex(#"[\n\t\s]+"#)

  static func load(pem: String) throws -> [SecCertificate] {

    return try pemRegex.allMatches(in: pem)
      .map { match in

        guard
          let capture = match.captures.first,
          let base64Data = capture?.replacingAll(matching: pemWhitespaceRegex, with: ""),
          let data = Data(base64Encoded: base64Data),
          let cert = SecCertificateCreateWithData(nil, data as CFData)
        else {
          throw SecCertificateError.loadFailed
        }

        return cert
      }
  }

}


#if os(iOS) || os(watchOS) || os(tvOS)
  // Add key usage options matching Apple provided macOS version
  //
  public struct SecKeyUsage: OptionSet {

    public let rawValue: UInt32

    public init(rawValue: UInt32) {
      self.rawValue = rawValue
    }

    // See: https://tools.ietf.org/html/rfc5280#section-4.2.1.3
    public static let unspecified: SecKeyUsage = []
    public static let digitalSignature = SecKeyUsage(rawValue: 1 << 0)
    public static let nonRepudiation = SecKeyUsage(rawValue: 1 << 1)
    public static let keyEncipherment = SecKeyUsage(rawValue: 1 << 2)
    public static let dataEncipherment = SecKeyUsage(rawValue: 1 << 3)
    public static let keyAgreement = SecKeyUsage(rawValue: 1 << 4)
    public static let keyCertSign = SecKeyUsage(rawValue: 1 << 5)
    public static let crlSign = SecKeyUsage(rawValue: 1 << 6)
    public static let encipherOnly = SecKeyUsage(rawValue: 1 << 7)
    public static let decipherOnly = SecKeyUsage(rawValue: 1 << 8)
    public static let critical = SecKeyUsage(rawValue: 1 << 31)
    public static let all = SecKeyUsage(rawValue: 0x7FFFFFFF)
  }
#endif
