//
//  CertificateBuilder.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
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

    public init(serialNumber: TBSCertificate.SerialNumber? = nil,
                issuer: Name? = nil, issuerUniqueID: TBSCertificate.UniqueIdentifier? = nil,
                subject: Name? = nil, subjectUniqueID: TBSCertificate.UniqueIdentifier? = nil,
                subjectPublicKeyInfo: SubjectPublicKeyInfo? = nil,
                notBefore: AnyTime? = nil, notAfter: AnyTime? = nil,
                extensions: Extensions? = nil) {
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

      var extensions: Extensions?
      if let requestExtensions = try reqInfo.attributes.first(Extensions.self) {
        var currentExtensions = self.extensions ?? Extensions()
        currentExtensions.replaceAll(requestExtensions)
        extensions = currentExtensions
      }

      return Builder(serialNumber: serialNumber,
                     issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: reqInfo.subject, subjectUniqueID: subjectUniqueID,
                     subjectPublicKeyInfo: reqInfo.subjectPKInfo,
                     notBefore: notBefore, notAfter: notAfter,
                     extensions: extensions)
    }

    public func serialNumber(_ serialNumber: TBSCertificate.SerialNumber) -> Builder {
      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func issuer(name issuer: Name, uniqueID issuerUniqueID: TBSCertificate.UniqueIdentifier? = nil) -> Builder {
      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func addIssuerAlternativeNames(names: GeneralName...) throws -> Builder {

      var extensions = self.extensions ?? Extensions()
      let currentNames = try extensions.first(IssuerAltName.self)?.names ?? []
      try extensions.replace(value: IssuerAltName(names: currentNames + names))

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func issuerAlternativeNames(names: GeneralName...) throws -> Builder {

      var extensions = self.extensions ?? Extensions()
      try extensions.replace(value: IssuerAltName(names: names))

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func subject(name subject: Name,
                        uniqueID subjectUniqueID: TBSCertificate.UniqueIdentifier? = nil) throws -> Builder {
      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func subjectUniqueID(_ subjectUniqueID: TBSCertificate.UniqueIdentifier) -> Builder {
      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func addSubjectAlternativeNames(names: GeneralName...) throws -> Builder {

      var extensions = self.extensions ?? Extensions()
      let currentNames = try extensions.first(SubjectAltName.self)?.names ?? []
      try extensions.replace(value: SubjectAltName(names: currentNames + names))

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func subjectAlternativeNames(names: GeneralName...) throws -> Builder {

      var extensions = self.extensions ?? Extensions()
      try extensions.replace(value: SubjectAltName(names: names))

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func publicKey(_ publicKey: Data,
                          algorithm: AlgorithmIdentifier,
                          usage keyUsage: KeyUsage? = nil) throws -> Builder {

      var extensions = self.extensions
      if let keyUsage = keyUsage {
        extensions = extensions ?? Extensions()
        extensions!.remove(KeyUsage.self)
        try extensions!.append(value: keyUsage)
      }

      let subjectPublicKeyInfo = SubjectPublicKeyInfo(algorithm: algorithm, subjectPublicKey: publicKey)

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func basicConstraints(ca: Bool, pathLength: Int? = nil) throws -> Builder {

      return try addExtension(value: BasicConstraints(ca: ca, pathLenConstraint: pathLength))
    }

    public func computeSubjectKeyIdentifier() throws -> Builder {

      guard let subjectPublicKey = subjectPublicKeyInfo?.subjectPublicKey else {
        throw Error.missingParameter("subjectPublicKeyInfo.subjectPublicKey")
      }

      let keyIdentifier = Digester.digest(subjectPublicKey, using: .sha1)

      return try subjectKeyIdentifier(keyIdentifier)
    }

    public func subjectKeyIdentifier(_ value: KeyIdentifier) throws -> Builder {

      return try addExtension(value: SubjectKeyIdentifier(value: value))
    }

    public func authorityKeyIdentifier(_ value: KeyIdentifier,
                                       certIssuer: GeneralNames? = nil,
                                       certSerialNumber: TBSCertificate.SerialNumber? = nil) throws -> Builder {

      return try addExtension(value: AuthorityKeyIdentifier(keyIdentifier: value,
                                                            authorityCertIssuer: certIssuer,
                                                            authorityCertSerialNumber: certSerialNumber))
    }

    public func addExtension<Value>(value: Value, isCritical: Bool) throws -> Builder where Value: ExtensionValue {

      var extensions = self.extensions ?? Extensions()
      try extensions.append(value: value, isCritical: isCritical)

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func addExtension<Value>(value: Value) throws -> Builder where Value: CriticalExtensionValue {

      var extensions = self.extensions ?? Extensions()
      try extensions.append(value: value)

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func addExtension<Value>(value: Value) throws -> Builder where Value: NonCriticalExtensionValue {

      var extensions = self.extensions ?? Extensions()
      try extensions.append(value: value)

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func addExtension(_ ext: Extension) throws -> Builder {

      var extensions = self.extensions ?? Extensions()
      extensions.append(ext)

      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: notAfter, extensions: extensions)
    }

    public func valid(from: Date = Date(), to: Date) -> Builder {
      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: time(of: from), notAfter: time(of: to), extensions: extensions)
    }

    public func valid(for timeInterval: TimeInterval) -> Builder {
      let validityEnd = Date().addingTimeInterval(timeInterval)
      return Builder(serialNumber: serialNumber, issuer: issuer, issuerUniqueID: issuerUniqueID,
                     subject: subject, subjectUniqueID: subjectUniqueID, subjectPublicKeyInfo: subjectPublicKeyInfo,
                     notBefore: notBefore, notAfter: time(of: validityEnd), extensions: extensions)
    }

    public func buildInfo(signatureAlgorithm: AlgorithmIdentifier) throws -> TBSCertificate {
      guard let issuer = self.issuer else { throw Error.missingParameter("issuer") }
      guard let subject = self.subject else { throw Error.missingParameter("subject") }
      guard let subjectPublicKeyInfo = self.subjectPublicKeyInfo else { throw Error.missingParameter("subjectPublicKeyInfo") }
      guard let notAfter = self.notAfter else { throw Error.missingParameter("notAfter/period") }
      let serialNumber = try self.serialNumber ?? Self.randomSerialNumber()
      let notBefore = self.notBefore ?? time(of: Date().addingTimeInterval(-Self.defaultValidityBeforeAllowance))
      let version = recommendedVersion
      return TBSCertificate(version: version, serialNumber: serialNumber, signature: signatureAlgorithm,
                            issuer: issuer,
                            validity: .init(notBefore: notBefore, notAfter: notAfter),
                            subject: subject, subjectPublicKeyInfo: subjectPublicKeyInfo,
                            issuerUniqueID: issuerUniqueID, subjectUniqueID: subjectUniqueID,
                            extensions: extensions)
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

    public static func randomSerialNumber() throws -> Integer {
      var data = (0 ..< 20).map { _ in UInt8.random(in: 0 ... UInt8.max) } // max is 20 octets
      data[0] &= 0x7F // must be non-negative
      return Integer(Data(data))
    }

  }

}

private func time(of date: Date) -> AnyTime {
  if date < maxUTCTime {
    return AnyTime(date.secondPrecision, kind: .utc)
  }
  return AnyTime(date.millisecondPrecision, kind: .generalized)
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
