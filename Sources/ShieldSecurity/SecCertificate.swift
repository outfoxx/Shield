//
//  SecCertificate.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
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
import OSLog


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

  var subjectName: Name? {
    guard let subjectData = SecCertificateCopyNormalizedSubjectSequence(self) else {
      return nil
    }
    do {
      return try ASN1Decoder(schema: Schemas.Name).decode(Name.self, from: subjectData as Data)
    }
    catch {
      Logger.default.error("Unable to parse subject name: \(error.localizedDescription, privacy: .public)")
      return nil
    }
  }

  var issuerName: Name? {
    guard let issuerData = SecCertificateCopyNormalizedIssuerSequence(self) else {
      return nil
    }
    do {
      return try ASN1Decoder(schema: Schemas.Name).decode(Name.self, from: issuerData as Data)
    }
    catch {
      Logger.default.error("Unable to parse issuer name: \(error.localizedDescription, privacy: .public)")
      return nil
    }
  }

  var publicKey: SecKey? {
    return SecCertificateCopyKey(self)
  }

  func publicKeyValidated(trustedCertificates: [SecCertificate]) throws -> SecKey {

    let trust = try createCertificateValidationTrust(anchorCertificates: trustedCertificates)

    try evaluateTrust(trust)

    guard let key = SecTrustCopyKey(trust) else {
      throw SecCertificateError.publicKeyRetrievalFailed
    }

    return key
  }

#if swift(>=5.5)
  func publicKeyValidated(trustedCertificates: [SecCertificate]) async throws -> SecKey {

    let trust = try createCertificateValidationTrust(anchorCertificates: trustedCertificates)

    try await evaluateTrust(trust)

    guard let key = SecTrustCopyKey(trust) else {
      throw SecCertificateError.publicKeyRetrievalFailed
    }

    return key
  }
#endif

  private func createCertificateValidationTrust(anchorCertificates: [SecCertificate]) throws -> SecTrust {

    let policy = SecPolicyCreateBasicX509()

    var trustResult: SecTrust?
    let status = SecTrustCreateWithCertificates(self, policy, &trustResult)
    guard let trust = trustResult, status == errSecSuccess else {
      throw SecCertificateError.trustCreationFailed
    }

    if SecTrustSetAnchorCertificates(trust, anchorCertificates as CFArray) != errSecSuccess {
      throw SecCertificateError.trustCreationFailed
    }

    return trust
  }

  private func evaluateTrust(_ trust: SecTrust) throws {
    var error: CFError?

    if !SecTrustEvaluateWithError(trust, &error) {
      try checkFailedTrustEvaluation(trust, error: error)
    }
  }

#if swift(>=5.5)
  private func evaluateTrust(_ trust: SecTrust) async throws {

    let (result, error): (Bool, CFError?) = try await withCheckedThrowingContinuation { continuation in

      let queue = DispatchQueue.global(qos: .default)
      queue.async {

        let status = SecTrustEvaluateAsyncWithError(trust, queue) { _, result, error in
          continuation.resume(with: .success((result, error)))
        }

        if status != errSecSuccess {
          continuation.resume(with: .failure(SecCertificateError.trustValidationError))
        }

      }
    }

    if !result {
      try checkFailedTrustEvaluation(trust, error: error)
    }
  }
#endif

  private func checkFailedTrustEvaluation(_ trust: SecTrust, error: CFError?) throws {

    var trustResult: SecTrustResultType = .otherError
    let trustResultStatus = SecTrustGetTrustResult(trust, &trustResult)
    if trustResultStatus != errSecSuccess {
      Logger.default.debug("Unable to retrieve trust result: \(trustResultStatus)")
      trustResult = .otherError
    }

    // `proceed` must be allowed
    if trustResult == SecTrustResultType.proceed {
      return
    }

    logTrustEvaluation(level: .error,
                       trust: trust,
                       result: trustResult,
                       error: error)

    throw SecCertificateError.trustValidationFailed
  }

  private func logTrustEvaluation(level: OSLogType,
                                  trust: SecTrust,
                                  result: SecTrustResultType,
                                  error: CFError?) {

    var anchorCertificatesArray: CFArray?
    let anchorCertificates: [SecCertificate]
    let anchorCertificatesStatus = SecTrustCopyCustomAnchorCertificates(trust, &anchorCertificatesArray)
    if anchorCertificatesStatus == errSecSuccess, let anchorCertificatesArray = anchorCertificatesArray {
      anchorCertificates = anchorCertificatesArray as! [SecCertificate] // swiftlint:disable:this force_cast
    }
    else {
      anchorCertificates = []
    }

    let errorDesc: String
    if let error = error {
      errorDesc = "\n" + error.humanReadableDescriptionLines.map { "    \($0)" }.joined(separator: "\n")
    }
    else {
      errorDesc = "None"
    }

    Logger.default.log(
      level: level,
      """
      Trust evaulation failed:
        Result: \(trustResultDescription(result: result), privacy: .public)
        Error: \(errorDesc)
        Certificate:
          \(self, privacy: .public)
        Anchor Certificates:
          \(anchorCertificates.enumerated().map { (idx, cert) in
            "\(idx): \(cert)" }.joined(separator: "\n    "), privacy: .public)
      """
    )
  }

  var pemEncoded: String {
    let pem = derEncoded.base64EncodedString().chunks(ofCount: 64).joined(separator: "\n")
    return "-----BEGIN CERTIFICATE-----\n\(pem)\n-----END CERTIFICATE-----"
  }

  var derEncoded: Data {
    return SecCertificateCopyData(self) as Data
  }

  func decode() throws -> Certificate {
    return try ASN1Decoder.decode(Certificate.self, from: derEncoded)
  }

  func attributes() throws -> [String: Any] {

    #if os(iOS) || os(watchOS) || os(tvOS)

      let query = [
        kSecReturnAttributes as String: kCFBooleanTrue!,
        kSecValueRef as String: self,
      ] as [String: Any] as CFDictionary

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

    return data as! [String: Any] // swiftlint:disable:this force_cast
  }

  func save() throws {

    let query = [
      kSecClass as String: kSecClassCertificate,
      kSecValueRef as String: self,
    ] as [String: Any] as CFDictionary

    var data: CFTypeRef?

    let status = SecItemAdd(query, &data)

    if status != errSecSuccess {
      throw SecCertificateError.saveFailed
    }
  }

  static func load(
    resourceName: String,
    inDirectory dir: String? = nil,
    in bundle: Bundle? = nil
  ) throws -> [SecCertificate]? {

    let bundle = bundle ?? Bundle.main

    if let loaded = try load(derResourceName: resourceName, inDirectory: dir, in: bundle) {
      return [loaded]
    }

    if let loaded = try load(pemResourceName: resourceName, inDirectory: dir, in: bundle) {
      return loaded
    }

    return nil
  }

  static func load(
    derResourceName: String,
    inDirectory dir: String? = nil,
    in bundle: Bundle? = nil
  ) throws -> SecCertificate? {

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

  static func load(
    pemResourceName: String,
    inDirectory dir: String? = nil,
    in bundle: Bundle? = nil
  ) throws -> [SecCertificate]? {

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

  private static let pemRegex =
    Regex(#"-----BEGIN CERTIFICATE-----\s*([a-zA-Z0-9\s/+]+=*)\s*-----END CERTIFICATE-----"#)
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

extension SecCertificate: CustomStringConvertible {

  public var description: String {
    return SecCertificateCopySubjectSummary(self) as String? ?? "<no certificate summary>"
  }
}

private func trustResultDescription(result: SecTrustResultType) -> String {
  switch result {
  case .invalid: return "Invalid"
  case .proceed: return "Proceed"
  case .deny: return "Deny"
  case .unspecified: return "Unspecified"
  case .recoverableTrustFailure: return "Recoverable Trust Failure"
  case .fatalTrustFailure: return "Fatal Trust Failure"
  case .otherError: return "Other Error"
  default: return "Unknown"
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
