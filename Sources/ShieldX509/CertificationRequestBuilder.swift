//
//  CertificationRequestBuilder.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public extension CertificationRequest {

  struct Builder {

    public enum Error: Swift.Error {
      case missingParameter(String)
    }

    let subject: Name?
    let subjectPKInfo: SubjectPublicKeyInfo?
    let attributes: CRAttributes?

    public init(subject: Name? = nil, subjectPKInfo: SubjectPublicKeyInfo? = nil, attributes: CRAttributes? = nil) {
      self.subject = subject
      self.subjectPKInfo = subjectPKInfo
      self.attributes = attributes
    }

    public func subject(name subject: Name) throws -> Builder {
      return Builder(subject: subject, subjectPKInfo: subjectPKInfo, attributes: attributes)
    }

    public func addAlternativeNames(names: GeneralName...) throws -> Builder {
      return try addAlternativeNames(names: names)
    }

    public func addAlternativeNames(names: GeneralNames) throws -> Builder {

      var attributes = self.attributes ?? CRAttributes()
      var extensions = try attributes.first(Extensions.self) ?? Extensions()

      let currentNames = try extensions.first(SubjectAltName.self)?.names ?? []
      try extensions.replace(value: SubjectAltName(names: currentNames + names))

      attributes.replace(singleValued: extensions)

      return Builder(subject: subject, subjectPKInfo: subjectPKInfo, attributes: attributes)
    }

    public func alternativeNames(names: GeneralName...) throws -> Builder {
      return try alternativeNames(names: names)
    }

    public func alternativeNames(names: GeneralNames) throws -> Builder {

      var attributes = self.attributes ?? CRAttributes()
      var extensions = try attributes.first(Extensions.self) ?? Extensions()

      try extensions.replace(value: SubjectAltName(names: names))

      attributes.replace(singleValued: extensions)

      return Builder(subject: subject, subjectPKInfo: subjectPKInfo, attributes: attributes)
    }

    public func publicKey(
      _ publicKey: Data,
      algorithm: AlgorithmIdentifier,
      usage keyUsage: KeyUsage? = nil
    ) throws -> Builder {

      var builder = self

      if let keyUsage = keyUsage {
        builder = try builder.extension(Extension(value: keyUsage))
      }

      let subjectPKInfo = SubjectPublicKeyInfo(algorithm: algorithm, subjectPublicKey: publicKey)

      return Builder(subject: builder.subject, subjectPKInfo: subjectPKInfo, attributes: builder.attributes)
    }

    public func extendedKeyUsage(keyPurposes: Set<OID>, isCritical: Bool) throws -> Builder {

      let extKeyUsage = ExtKeyUsage(keyPurposes: keyPurposes)

      return try `extension`(Extension(value: extKeyUsage, critical: isCritical))
    }

    public func `extension`(_ extension: Extension) throws -> Builder {

      var attributes = self.attributes ?? CRAttributes()
      var extensions = try attributes.first(Extensions.self) ?? Extensions()

      extensions.replace(`extension`)

      attributes.replace(singleValued: extensions)

      return Builder(subject: subject, subjectPKInfo: subjectPKInfo, attributes: attributes)
    }

    public func buildInfo() throws -> CertificationRequestInfo {
      guard let subject = self.subject else { throw Error.missingParameter("subject") }
      guard let subjectPKInfo = self.subjectPKInfo else { throw Error.missingParameter("subjectPKInfo") }
      return CertificationRequestInfo(
        version: .v1,
        subject: subject,
        subjectPKInfo: subjectPKInfo,
        attributes: attributes
      )
    }

  }

}
