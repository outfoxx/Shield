//
//  CertificateBuilder.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldCrypto


public extension Certificate {

  struct Builder {

    public static let defaultValidityBeforeAllowance: TimeInterval = 2

    public enum Error: Swift.Error {
      case missingParameter(String)
    }

    let serialNumber: TBSCertificate.SerialNumber?
    let issuer: Name?
    let issuerUniqueID: TBSCertificate.UniqueIdentifier?
    let subject: Name?
    let subjectUniqueID: TBSCertificate.UniqueIdentifier?
    let subjectPublicKeyInfo: SubjectPublicKeyInfo?
    let notBefore: AnyTime?
    let notAfter: AnyTime?
    let extensions: Extensions?

    public init(
      serialNumber: TBSCertificate.SerialNumber? = nil,
      issuer: Name? = nil,
      issuerUniqueID: TBSCertificate.UniqueIdentifier? = nil,
      subject: Name? = nil,
      subjectUniqueID: TBSCertificate.UniqueIdentifier? = nil,
      subjectPublicKeyInfo: SubjectPublicKeyInfo? = nil,
      notBefore: AnyTime? = nil,
      notAfter: AnyTime? = nil,
      extensions: Extensions? = nil
    ) {
      self.serialNumber = serialNumber
      self.issuer = issuer
      self.issuerUniqueID = issuerUniqueID
      self.subject = subject
      self.subjectUniqueID = subjectUniqueID
      self.subjectPublicKeyInfo = subjectPublicKeyInfo
      self.notBefore = notBefore
      self.notAfter = notAfter
      self.extensions = extensions
    }

    public func request(_ req: CertificationRequest) throws -> Builder {
      return try request(req.certificationRequestInfo)
    }

    public func request(_ reqInfo: CertificationRequestInfo) throws -> Builder {

      var updatedExtensions: Extensions?
      if let requestExtensions = try reqInfo.attributes?.first(Extensions.self) {
        var currentExtensions = self.extensions ?? Extensions()
        currentExtensions.replaceAll(requestExtensions)
        updatedExtensions = currentExtensions
      }

      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: reqInfo.subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: reqInfo.subjectPKInfo,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: updatedExtensions
      )
    }

    public func serialNumber(_ serialNumber: TBSCertificate.SerialNumber) -> Builder {
      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: extensions
      )
    }

    public func issuer(name issuer: Name, uniqueID issuerUniqueID: TBSCertificate.UniqueIdentifier? = nil) -> Builder {
      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: extensions
      )
    }

    public func addIssuerAlternativeNames(names: GeneralName...) throws -> Builder {
      return try addIssuerAlternativeNames(names: names)
    }

    public func addIssuerAlternativeNames(names: GeneralNames) throws -> Builder {

      let currentExtension = self.extensions ?? Extensions()
      let currentNames = try currentExtension.first(IssuerAltName.self)?.names ?? []

      return try issuerAlternativeNames(names: currentNames + names)
    }

    public func issuerAlternativeNames(names: GeneralName...) throws -> Builder {
      return try issuerAlternativeNames(names: names)
    }

    public func issuerAlternativeNames(names: GeneralNames) throws -> Builder {

      var updatedExtensions = self.extensions ?? Extensions()
      try updatedExtensions.replace(value: IssuerAltName(names: names))

      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: updatedExtensions
      )
    }

    public func subject(
      name subject: Name,
      uniqueID subjectUniqueID: TBSCertificate.UniqueIdentifier? = nil
    ) throws -> Builder {
      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: extensions
      )
    }

    public func subjectUniqueID(_ subjectUniqueID: TBSCertificate.UniqueIdentifier) -> Builder {
      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: extensions
      )
    }

    public func addSubjectAlternativeNames(names: GeneralName...) throws -> Builder {
      return try addSubjectAlternativeNames(names: names)
    }

    public func addSubjectAlternativeNames(names: GeneralNames) throws -> Builder {

      let currentExtension = self.extensions ?? Extensions()
      let currentNames = try currentExtension.first(SubjectAltName.self)?.names ?? []

      return try subjectAlternativeNames(names: currentNames + names)
    }

    public func subjectAlternativeNames(names: GeneralName...) throws -> Builder {
      return try subjectAlternativeNames(names: names)
    }

    public func subjectAlternativeNames(names: GeneralNames) throws -> Builder {
      var updatedExtensions = self.extensions ?? Extensions()
      try updatedExtensions.replace(value: SubjectAltName(names: names))

      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: updatedExtensions
      )
    }

    public func publicKey(
      _ publicKey: BitString,
      algorithm: AlgorithmIdentifier,
      usage keyUsage: KeyUsage? = nil
    ) throws -> Builder {

      var updatedExtensions = self.extensions
      if let keyUsage = keyUsage {
        updatedExtensions = updatedExtensions ?? Extensions()
        try updatedExtensions!.replace(value: keyUsage)
      }

      let updatedSubjectPKI = SubjectPublicKeyInfo(algorithm: algorithm, subjectPublicKey: publicKey)

      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: updatedSubjectPKI,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: updatedExtensions
      )
    }

    public func extendedKeyUsage(keyPurposes: Set<OID>, isCritical: Bool) throws -> Builder {

      return try addExtension(value: ExtKeyUsage(keyPurposes: keyPurposes), isCritical: isCritical)
    }

    public func basicConstraints(ca: Bool, pathLength: Int? = nil) throws -> Builder {

      return try addExtension(value: BasicConstraints(ca: ca, pathLenConstraint: pathLength))
    }

    public func computeSubjectKeyIdentifier() throws -> Builder {

      guard let subjectPublicKey = subjectPublicKeyInfo?.subjectPublicKey else {
        throw Error.missingParameter("subjectPublicKeyInfo.subjectPublicKey")
      }

      let keyIdentifier = Digester.digest(subjectPublicKey.bytes, using: .sha1)

      return try subjectKeyIdentifier(keyIdentifier)
    }

    public func subjectKeyIdentifier(_ value: KeyIdentifier) throws -> Builder {

      return try addExtension(value: SubjectKeyIdentifier(value: value))
    }

    public func authorityKeyIdentifier(
      _ value: KeyIdentifier,
      certIssuer: GeneralNames? = nil,
      certSerialNumber: TBSCertificate.SerialNumber? = nil
    ) throws -> Builder {

      return try addExtension(value: AuthorityKeyIdentifier(
        keyIdentifier: value,
        authorityCertIssuer: certIssuer,
        authorityCertSerialNumber: certSerialNumber
      ))
    }

    public func addExtension<Value>(value: Value, isCritical: Bool) throws -> Builder where Value: ExtensionValue {
      return try addExtension(Extension(extnId: Value.extensionID, critical: isCritical, extnValue: try value.encoded()))
    }

    public func addExtension<Value>(value: Value) throws -> Builder where Value: CriticalExtensionValue {
      return try addExtension(Extension(extnId: Value.extensionID, critical: true, extnValue: try value.encoded()))
    }

    public func addExtension<Value>(value: Value) throws -> Builder where Value: NonCriticalExtensionValue {
      return try addExtension(Extension(extnId: Value.extensionID, critical: false, extnValue: try value.encoded()))
    }

    public func addExtension(_ ext: Extension) throws -> Builder {

      var updatedExtensions = self.extensions ?? Extensions()
      updatedExtensions.append(ext)

      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: notBefore,
        notAfter: notAfter,
        extensions: updatedExtensions
      )
    }

    public func valid(from: Date = Date(), to: Date) -> Builder {
      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: time(of: from),
        notAfter: time(of: to),
        extensions: extensions
      )
    }

    public func valid(for timeInterval: TimeInterval) -> Builder {
      let validityEnd = Date().addingTimeInterval(timeInterval)
      return Builder(
        serialNumber: serialNumber,
        issuer: issuer,
        issuerUniqueID: issuerUniqueID,
        subject: subject,
        subjectUniqueID: subjectUniqueID,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        notBefore: notBefore,
        notAfter: time(of: validityEnd),
        extensions: extensions
      )
    }

    public func buildInfo(signatureAlgorithm: AlgorithmIdentifier) throws -> TBSCertificate {
      guard let issuer = self.issuer else { throw Error.missingParameter("issuer") }
      guard let subject = self.subject else { throw Error.missingParameter("subject") }
      guard let subjectPublicKeyInfo = self.subjectPublicKeyInfo else { throw Error.missingParameter("subjectPublicKeyInfo") }
      guard let notAfter = self.notAfter else { throw Error.missingParameter("notAfter/period") }
      let serialNumber = try self.serialNumber ?? Self.randomSerialNumber()
      let notBefore = self.notBefore ?? time(of: Date().addingTimeInterval(-Self.defaultValidityBeforeAllowance))
      let version = recommendedVersion
      return TBSCertificate(
        version: version,
        serialNumber: serialNumber,
        signature: signatureAlgorithm,
        issuer: issuer,
        validity: .init(notBefore: notBefore, notAfter: notAfter),
        subject: subject,
        subjectPublicKeyInfo: subjectPublicKeyInfo,
        issuerUniqueID: issuerUniqueID,
        subjectUniqueID: subjectUniqueID,
        extensions: extensions
      )
    }

    private var recommendedVersion: TBSCertificate.Version {
      if extensions != nil {
        return .v3
      }
      if hasUniqueIDs {
        return .v2
      }
      return .v1
    }

    private var hasUniqueIDs: Bool {
      return issuerUniqueID != nil || subjectUniqueID != nil
    }

    public static func randomSerialNumber() throws -> ASN1.Integer {
      var data = (0 ..< 20).map { _ in UInt8.random(in: 0 ... UInt8.max) } // max is 20 octets
      data[0] &= 0x7F // must be non-negative
      return ASN1.Integer(derEncoded: Data(data))
    }

  }

}

private func time(of date: Date) -> AnyTime {
  if date < maxUTCTime {
    return AnyTime(date: date.secondPrecision, timeZone: .utc, kind: .utc)
  }
  return AnyTime(date: date.millisecondPrecision, timeZone: .utc, kind: .generalized)
}

private let maxUTCTime: Date = {
  var date = DateComponents()
  date.year = 2050
  date.month = 1
  date.day = 1
  date.hour = 0
  date.minute = 0
  date.second = 0
  date.nanosecond = 0
  return Calendar.current.date(from: date)!
}()


private extension Date {

  var millisecondPrecision: Date {
    return Date(timeIntervalSinceReferenceDate: (timeIntervalSinceReferenceDate * 1000.0).rounded() / 1000.0)
  }

  var secondPrecision: Date {
    return Date(timeIntervalSinceReferenceDate: timeIntervalSinceReferenceDate.rounded())
  }

}
