//
//  CertificationRequestBuilder.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation


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

    public func addAlternativeNames(names: [GeneralName]) throws -> Builder {

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

    public func alternativeNames(names: [GeneralName]) throws -> Builder {

      var attributes = self.attributes ?? CRAttributes()
      var extensions = try attributes.first(Extensions.self) ?? Extensions()

      try extensions.replace(value: SubjectAltName(names: names))

      attributes.replace(singleValued: extensions)

      return Builder(subject: subject, subjectPKInfo: subjectPKInfo, attributes: attributes)
    }

    public func publicKey(_ publicKey: Data,
                          algorithm: AlgorithmIdentifier,
                          usage keyUsage: KeyUsage? = nil) throws -> Builder {

      var attributes = self.attributes
      if let keyUsage = keyUsage {
        attributes = attributes ?? CRAttributes()
        var extensions = try attributes!.first(Extensions.self) ?? Extensions()
        extensions.remove(KeyUsage.self)
        try extensions.append(value: keyUsage)

        attributes!.remove(Extensions.self)
        attributes!.append(singleValued: extensions)
      }

      let subjectPKInfo = SubjectPublicKeyInfo(algorithm: algorithm, subjectPublicKey: publicKey)

      return Builder(subject: subject, subjectPKInfo: subjectPKInfo, attributes: attributes)
    }

    public func buildInfo() throws -> CertificationRequestInfo {
      guard let subject = self.subject else { throw Error.missingParameter("subject") }
      guard let subjectPKInfo = self.subjectPKInfo else { throw Error.missingParameter("subjectPKInfo") }
      let attributes = self.attributes ?? CRAttributes()
      return CertificationRequestInfo(version: .v1,
                                      subject: subject,
                                      subjectPKInfo: subjectPKInfo,
                                      attributes: attributes)
    }

  }

}
