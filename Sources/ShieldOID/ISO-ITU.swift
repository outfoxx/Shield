//
//  ISO-ITU.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation

// swiftformat:disable consecutiveSpaces

/// Areas of joint work between ISO/IEC (International Organization for Standardization/International Electrotechnical Commission)
/// and ITU-T (International Telecommunication Union - Telecommunication standardization sector), and other international work
///
/// See: http://oid-info.com/get/2
///
public struct iso_itu: OIDBranch {
  public static let id: UInt64 = 2
  public static let names = ["joint-iso-itu-t", "joint-iso-ccitt"]
  internal static let children: [OIDNode.Type] = [ds.self]

  public struct ds: OIDBranch {
    public static let id: UInt64 = 5
    public static let names = ["ds"]
    internal static let children: [OIDNode.Type] = [attributeType.self, certificateExtension.self]

    public enum attributeType: OID, CaseIterable, OIDLeaf {
      public static let id: UInt64 = 4
      public static let names = ["attributeType"]
      internal static let children: [OIDNode.Type] = []

      case objectClass =                            "2.5.4.0"
      case aliasedEntryName =                       "2.5.4.1"
      case knowledgeInformation =                   "2.5.4.2"
      case commonName =                             "2.5.4.3"
      case surname =                                "2.5.4.4"
      case serialNumber =                           "2.5.4.5"
      case countryName =                            "2.5.4.6"
      case localityName =                           "2.5.4.7"
      case stateOrProvinceName =                    "2.5.4.8"
      case streetAddress =                          "2.5.4.9"
      case organizationName =                       "2.5.4.10"
      case organizationalUnitName =                 "2.5.4.11"
      case title =                                  "2.5.4.12"
      case description =                            "2.5.4.13"
      case searchGuide =                            "2.5.4.14"
      case businessCategory =                       "2.5.4.15"
      case postalAddress =                          "2.5.4.16"
      case postalCode =                             "2.5.4.17"
      case postOfficeBox =                          "2.5.4.18"
      case physicalDeliveryOfficeName =             "2.5.4.19"
      case telephoneNumber =                        "2.5.4.20"
      case telexNumber =                            "2.5.4.21"
      case teletexTerminalIdentifier =              "2.5.4.22"
      case facsimileTelephoneNumber =               "2.5.4.23"
      case x121Address =                            "2.5.4.24"
      case internationalISDNNumber =                "2.5.4.25"
      case registeredAddress =                      "2.5.4.26"
      case destinationIndicator =                   "2.5.4.27"
      case preferredDeliveryMethod =                "2.5.4.28"
      case presentationAddress =                    "2.5.4.29"
      case supportedApplicationContext =            "2.5.4.30"
      case member =                                 "2.5.4.31"
      case owner =                                  "2.5.4.32"
      case roleOccupant =                           "2.5.4.33"
      case seeAlso =                                "2.5.4.34"
      case userPassword =                           "2.5.4.35"
      case userCertificate =                        "2.5.4.36"
      case caCertificate =                          "2.5.4.37"
      case authorityRevocationList =                "2.5.4.38"
      case certificateRevocationList =              "2.5.4.39"
      case crossCertificatePair =                   "2.5.4.40"
      case name =                                   "2.5.4.41"
      case givenName =                              "2.5.4.42"
      case initials =                               "2.5.4.43"
      case generationQualifier =                    "2.5.4.44"
      case uniqueIdentifier =                       "2.5.4.45"
      case dnQualifier =                            "2.5.4.46"
      case enhancedSearchGuide =                    "2.5.4.47"
      case protocolInformation =                    "2.5.4.48"
      case distinguishedName =                      "2.5.4.49"
      case uniqueMember =                           "2.5.4.50"
      case houseIdentifier =                        "2.5.4.51"
      case supportedAlgorithms =                    "2.5.4.52"
      case deltaRevocationList =                    "2.5.4.53"
      case dmdName =                                "2.5.4.54"
      case clearance =                              "2.5.4.55"
      case defaultDirQop =                          "2.5.4.56"
      case attributeIntegrityInfo =                 "2.5.4.57"
      case attributeCertificate =                   "2.5.4.58"
      case attributeCertificateRevocationList =     "2.5.4.59"
      case confKeyInfo =                            "2.5.4.60"
      case aaCertificate =                          "2.5.4.61"
      case attributeDescriptorCertificate =         "2.5.4.62"
      case attributeAuthorityRevocationList =       "2.5.4.63"
      case family =                                 "2.5.4.64"
      case pseudonym =                              "2.5.4.65"
      case communicationsService =                  "2.5.4.66"
      case communicationsNetwork =                  "2.5.4.67"
      case certificationPracticeStmt =              "2.5.4.68"
      case certificatePolicy =                      "2.5.4.69"
      case pkiPath =                                "2.5.4.70"
      case privPolicy =                             "2.5.4.71"
      case role =                                   "2.5.4.72"
      case delegationPath =                         "2.5.4.73"
      case protPrivPolicy =                         "2.5.4.74"
      case xmlPrivilegeInfo =                       "2.5.4.75"
      case xmlPrivPolicy =                          "2.5.4.76"
      case uuidpair =                               "2.5.4.77"
      case tagOid =                                 "2.5.4.78"
      case uiiFormat =                              "2.5.4.79"
      case uiiInUrh =                               "2.5.4.80"
      case contentUrl =                             "2.5.4.81"
      case permission =                             "2.5.4.82"
      case uri =                                    "2.5.4.83"
      case pwdAttribute =                           "2.5.4.84"
      case userPwd =                                "2.5.4.85"
      case urn =                                    "2.5.4.86"
      case url =                                    "2.5.4.87"
      case utmCoordinates =                         "2.5.4.88"
      case urnC =                                   "2.5.4.89"
      case uii =                                    "2.5.4.90"
      case epc =                                    "2.5.4.91"
      case tagAfi =                                 "2.5.4.92"
      case epcFormat =                              "2.5.4.93"
      case epcInUrn =                               "2.5.4.94"
      case ldapUrl =                                "2.5.4.95"
      case tagLocation =                            "2.5.4.96"
      case organizationIdentifier =                 "2.5.4.97"
    }

    public enum certificateExtension: OID, CaseIterable, OIDLeaf {
      public static let id: UInt64 = 29
      public static let names = ["certificateExtension"]
      internal static let children: [OIDNode.Type] = []

      case _authorityKeyIdentifier =                "2.5.29.1"
      case keyAttributes =                          "2.5.29.2"
      case _certificatePolicies =                   "2.5.29.3"
      case keyUsageRestriction =                    "2.5.29.4"
      case policyMapping =                          "2.5.29.5"
      case subtreesConstraint =                     "2.5.29.6"
      case _subjectAltName =                        "2.5.29.7"
      case _issuerAltName =                         "2.5.29.8"
      case subjectDirectoryAttributes =             "2.5.29.9"
      case _basicConstraints =                      "2.5.29.10"
      case subjectKeyIdentifier =                   "2.5.29.14"
      case keyUsage =                               "2.5.29.15"
      case privateKeyUsagePeriod =                  "2.5.29.16"
      case subjectAltName =                         "2.5.29.17"
      case issuerAltName =                          "2.5.29.18"
      case basicConstraints =                       "2.5.29.19"
      case crlNumber =                              "2.5.29.20"
      case reasonCode =                             "2.5.29.21"
      case expirationDate =                         "2.5.29.22"
      case instructionCode =                        "2.5.29.23"
      case invalidityDate =                         "2.5.29.24"
      case _crlDistributionPoints =                 "2.5.29.25"
      case _issuingDistributionPoint =              "2.5.29.26"
      case deltaCRLIndicator =                      "2.5.29.27"
      case issuingDistributionPoint =               "2.5.29.28"
      case certificateIssuer =                      "2.5.29.29"
      case nameConstraints =                        "2.5.29.30"
      case crlDistributionPoints =                  "2.5.29.31"
      case certificatePolicies =                    "2.5.29.32"
      case policyMappings =                         "2.5.29.33"
      case _policyConstraints =                     "2.5.29.34"
      case authorityKeyIdentifier =                 "2.5.29.35"
      case policyConstraints =                      "2.5.29.36"
      case extKeyUsage =                            "2.5.29.37"
      case authorityAttributeIdentifier =           "2.5.29.38"
      case roleSpecCertIdentifier =                 "2.5.29.39"
      case crlStreamIdentifier =                    "2.5.29.40"
      case basicAttConstraints =                    "2.5.29.41"
      case delegatedNameConstraints =               "2.5.29.42"
      case timeSpecification =                      "2.5.29.43"
      case crlScope =                               "2.5.29.44"
      case statusReferrals =                        "2.5.29.45"
      case freshestCRL =                            "2.5.29.46"
      case orderedList =                            "2.5.29.47"
      case attributeDescriptor =                    "2.5.29.48"
      case userNotice =                             "2.5.29.49"
      case soaIdentifier =                          "2.5.29.50"
      case baseUpdateTime =                         "2.5.29.51"
      case acceptableCertPolicies =                 "2.5.29.52"
      case deltaInfo =                              "2.5.29.53"
      case inhibitAnyPolicy =                       "2.5.29.54"
      case targetInformation =                      "2.5.29.55"
      case noRevAvail =                             "2.5.29.56"
      case acceptablePrivilegePolicies =            "2.5.29.57"
    }
  }
}
