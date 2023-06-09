//
//  ISO.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1

// swiftformat:disable consecutiveSpaces
// swiftlint:disable type_name identifier_name nesting

/// International Organization for Standardization (ISO)
///
/// See: http://oid-info.com/get/1
///
public struct iso: OIDBranch {
  public static let id: UInt64 = 1
  public static let names = ["iso"]
  internal static let children: [OIDNode.Type] = [memberBody.self, org.self]

  public struct memberBody: OIDBranch {
    public static let id: UInt64 = 2
    public static let names = ["member-body"]
    internal static let children: [OIDNode.Type] = [us.self]

    public struct us: OIDBranch {
      public static let id: UInt64 = 840
      public static let names = ["us"]
      internal static let children: [OIDNode.Type] = [rsadsi.self, ansix962.self]

      public struct rsadsi: OIDBranch {
        public static let id: UInt64 = 113549
        public static let names = ["rsadsi"]
        internal static let children: [OIDNode.Type] = [pkcs.self]

        public struct pkcs: OIDBranch {
          public static let id: UInt64 = 1
          public static let names = ["pkcs"]
          internal static let children: [OIDNode.Type] = [pkcs1.self, pkcs9.self]

          public enum pkcs1: OID, CaseIterable, OIDLeaf {
            public static let id: UInt64 = 1
            public static let names = ["pkcs-1"]

            case rsaEncryption =                    "1.2.840.113549.1.1.1"
            case md2WithRSAEncryption =             "1.2.840.113549.1.1.2"
            case md4WithRSAEncryption =             "1.2.840.113549.1.1.3"
            case md5WithRSAEncryption =             "1.2.840.113549.1.1.4"
            case sha1WithRSASignature =             "1.2.840.113549.1.1.5"
            case sha256WithRSAEncryption =          "1.2.840.113549.1.1.11"
            case sha384WithRSAEncryption =          "1.2.840.113549.1.1.12"
            case sha512WithRSAEncryption =          "1.2.840.113549.1.1.13"
            case sha224WithRSAEncryption =          "1.2.840.113549.1.1.14"
          }

          public enum pkcs5: OID, CaseIterable, OIDLeaf {
            public static let id: UInt64 = 5
            public static let names = ["pkcs-5"]

            case pbkdf2 =                           "1.2.840.113549.1.5.12"
            case pbes2 =                            "1.2.840.113549.1.5.13"
          }

          public enum pkcs9: OID, CaseIterable, OIDLeaf {
            public static let id: UInt64 = 9
            public static let names = ["pkcs-9"]

            case emailAddress =                     "1.2.840.113549.1.9.1"
            case unstructuredName =                 "1.2.840.113549.1.9.2"
            case contentType =                      "1.2.840.113549.1.9.3"
            case messageDigest =                    "1.2.840.113549.1.9.4"
            case signingTime =                      "1.2.840.113549.1.9.5"
            case counterSignature =                 "1.2.840.113549.1.9.6"
            case challengePassword =                "1.2.840.113549.1.9.7"
            case unstructuredAddress =              "1.2.840.113549.1.9.8"
            case extendedCertificateAttributes =    "1.2.840.113549.1.9.9"
            case extensionRequest =                 "1.2.840.113549.1.9.14"
          }
        }

        public enum digestAlgorithm: OID, CaseIterable, OIDLeaf {
          public static let id: UInt64 = 2
          public static let names = ["digestAlgorithm"]

          case hmacWithSHA1 =                     "1.2.840.113549.2.7"
          case hmacWithSHA224 =                   "1.2.840.113549.2.8"
          case hmacWithSHA256 =                   "1.2.840.113549.2.9"
          case hmacWithSHA384 =                   "1.2.840.113549.2.10"
          case hmacWithSHA512 =                   "1.2.840.113549.2.11"
          case hhmacWithSHA512_224 =              "1.2.840.113549.2.12"
          case hhmacWithSHA512_256 =              "1.2.840.113549.2.13"
        }

        public enum encryptionAlgorithm: OID, CaseIterable, OIDLeaf {
          public static let id: UInt64 = 3
          public static let names = ["encryptionAlgorithm", "encryptionalgorithm"]

          case rc2CBC =                           "1.2.840.113549.3.2"
          case rc2ECB =                           "1.2.840.113549.3.3"
          case rc4 =                              "1.2.840.113549.3.4"
          case rc4WithMAC =                       "1.2.840.113549.3.5"
          case desxCBC =                          "1.2.840.113549.3.6"
          case desEDE3CBC =                       "1.2.840.113549.3.7"
          case rc5CBC =                           "1.2.840.113549.3.8"
          case rc5CBCPad =                        "1.2.840.113549.3.9"
          case desCDMF =                          "1.2.840.113549.3.10"
          case desEDE3 =                          "1.2.840.113549.3.17"
        }

      }

      public struct ansix962: OIDBranch {
        public static let id: UInt64 = 10045
        public static let names = ["ansi-x962"]
        internal static let children: [OIDNode.Type] = [keyType.self]

        public enum keyType: OID, CaseIterable, OIDLeaf {
          public static let id: UInt64 = 2
          public static let names = ["keyType"]

          case ecPublicKey =                        "1.2.840.10045.2.1"
        }

        public struct curves: OIDBranch {
          public static let id: UInt64 = 3
          public static let names = ["curves"]
          internal static let children: [OIDNode.Type] = [characteristicTwo.self, prime.self]

          public enum characteristicTwo: OID, CaseIterable, OIDLeaf {
            public static let id: UInt64 = 0
            public static let names = ["characteristicTwo"]

            case c2pnb163v1 =                       "1.2.840.10045.3.0.1"
            case c2pnb163v2 =                       "1.2.840.10045.3.0.2"
            case c2pnb163v3 =                       "1.2.840.10045.3.0.3"
            case c2pnb176w1 =                       "1.2.840.10045.3.0.4"
            case c2tnb191v1 =                       "1.2.840.10045.3.0.5"
            case c2tnb191v2 =                       "1.2.840.10045.3.0.6"
            case c2tnb191v3 =                       "1.2.840.10045.3.0.7"
            case c2onb191v4 =                       "1.2.840.10045.3.0.8"
            case c2onb191v5 =                       "1.2.840.10045.3.0.9"
            case c2pnb208w1 =                       "1.2.840.10045.3.0.10"
            case c2tnb239v1 =                       "1.2.840.10045.3.0.11"
            case c2tnb239v2 =                       "1.2.840.10045.3.0.12"
            case c2tnb239v3 =                       "1.2.840.10045.3.0.13"
            case c2onb239v4 =                       "1.2.840.10045.3.0.14"
            case c2onb239v5 =                       "1.2.840.10045.3.0.15"
            case c2pnb272W1 =                       "1.2.840.10045.3.0.16"
            case c2pnb304W1 =                       "1.2.840.10045.3.0.17"
            case c2tnb359v1 =                       "1.2.840.10045.3.0.18"
            case c2pnb368w1 =                       "1.2.840.10045.3.0.19"
            case c2tnb431r1 =                       "1.2.840.10045.3.0.20"
          }

          public enum prime: OID, CaseIterable, OIDLeaf {
            public static let id: UInt64 = 1
            public static let names = ["prime"]

            case prime192v1 =                       "1.2.840.10045.3.1.1"
            case prime192v2 =                       "1.2.840.10045.3.1.2"
            case prime192v3 =                       "1.2.840.10045.3.1.3"
            case prime239v1 =                       "1.2.840.10045.3.1.4"
            case prime239v2 =                       "1.2.840.10045.3.1.5"
            case prime239v3 =                       "1.2.840.10045.3.1.6"
            case prime256v1 =                       "1.2.840.10045.3.1.7"
          }
        }

        public enum signatures: OID, CaseIterable, OIDBranch, OIDLeaf {
          public static let id: UInt64 = 4
          public static let names = ["signatures"]
          internal static let children: [OIDNode.Type] = [ecdsaWithSHA2.self]

          case ecdsaWithSHA1 =                      "1.2.840.10045.4.1"
          case ecdsaWithRecommended =               "1.2.840.10045.4.2"

          public enum ecdsaWithSHA2: OID, CaseIterable, OIDLeaf {
            public static let id: UInt64 = 3
            public static let names = ["ecdsaWithSHA2"]

            case ecdsaWithSHA224 =                  "1.2.840.10045.4.3.1"
            case ecdsaWithSHA256 =                  "1.2.840.10045.4.3.2"
            case ecdsaWithSHA384 =                  "1.2.840.10045.4.3.3"
            case ecdsaWithSHA512 =                  "1.2.840.10045.4.3.4"
          }
        }
      }
    }
  }

  public struct org: OIDBranch {
    public static let id: UInt64 = 3
    public static let names = ["org", "identified-organization", "iso-identified-organization"]
    internal static let children: [OIDNode.Type] = [certicom.self, dod.self]

    public struct dod: OIDBranch {
      public static let id: UInt64 = 6
      public static let names = ["dod"]
      internal static let children: [OIDNode.Type] = [internet.self]

      public struct internet: OIDBranch {
        public static let id: UInt64 = 1
        public static let names = ["internet"]
        internal static let children: [OIDNode.Type] = [security.self]

        public struct security: OIDBranch {
          public static let id: UInt64 = 5
          public static let names = ["security"]
          internal static let children: [OIDNode.Type] = [mechanisms.self]

          public struct mechanisms: OIDBranch {
            public static let id: UInt64 = 5
            public static let names = ["mechanisms"]
            internal static let children: [OIDNode.Type] = [pkix.self]

            public struct pkix: OIDBranch {
              public static let id: UInt64 = 7
              public static let names = ["pkix"]
              internal static let children: [OIDNode.Type] = [kp.self]

              public enum kp: OID, CaseIterable, OIDLeaf {
                public static let id: UInt64 = 3
                public static let names = ["kp"]

                case serverAuth =                   "1.3.6.1.5.5.7.3.1"
                case clientAuth =                   "1.3.6.1.5.5.7.3.2"
                case codeSigning =                  "1.3.6.1.5.5.7.3.3"
                case emailProtection =              "1.3.6.1.5.5.7.3.4"
                case ipsecEndSystem =               "1.3.6.1.5.5.7.3.5"
                case ipsecTunnel =                  "1.3.6.1.5.5.7.3.6"
                case ipsecUser =                    "1.3.6.1.5.5.7.3.7"
                case timeStamping =                 "1.3.6.1.5.5.7.3.8"
                case ocspSigning =                  "1.3.6.1.5.5.7.3.9"
                case dvcs =                         "1.3.6.1.5.5.7.3.10"
                case sbgpCertAAServerAuth =         "1.3.6.1.5.5.7.3.11"
                case idKpScvpResponder =            "1.3.6.1.5.5.7.3.12"
                case idKpEapOverPPP =               "1.3.6.1.5.5.7.3.13"
                case idKpEapOverLAN =               "1.3.6.1.5.5.7.3.14"
                case idKpScvpServer =               "1.3.6.1.5.5.7.3.15"
                case idKpScvpClient =               "1.3.6.1.5.5.7.3.16"
                case idKpIpsecIKE =                 "1.3.6.1.5.5.7.3.17"
                case idKpCapwapAC =                 "1.3.6.1.5.5.7.3.18"
                case idKpCapwapWTP =                "1.3.6.1.5.5.7.3.19"
                case idKpSipDomain =                "1.3.6.1.5.5.7.3.20"
                case secureShellClient =            "1.3.6.1.5.5.7.3.21"
                case secureShellServer =            "1.3.6.1.5.5.7.3.22"
                case idKpSendRouter =               "1.3.6.1.5.5.7.3.23"
                case idKpSendProxy =                "1.3.6.1.5.5.7.3.24"
                case idKpSendOwner =                "1.3.6.1.5.5.7.3.25"
                case idKpSendProxiedOwner =         "1.3.6.1.5.5.7.3.26"
                case idKpCmcCA =                    "1.3.6.1.5.5.7.3.27"
                case idKpCmcRA =                    "1.3.6.1.5.5.7.3.28"
                case idKpCmcArchive =               "1.3.6.1.5.5.7.3.29"
              }

            }

          }

        }

      }

    }

    public struct certicom: OIDBranch {
      public static let id: UInt64 = 132
      public static let names = ["certicom"]
      internal static let children: [OIDNode.Type] = [curve.self, schemes.self]

      public enum curve: OID, CaseIterable, OIDLeaf {
        public static let id: UInt64 = 0
        public static let names = ["curve"]

        case ansit163k1 =                           "1.3.132.0.1"
        case ansit163r1 =                           "1.3.132.0.2"
        case ansit239k1 =                           "1.3.132.0.3"
        case sect113r1 =                            "1.3.132.0.4"
        case sect113r2 =                            "1.3.132.0.5"
        case secp112r1 =                            "1.3.132.0.6"
        case secp112r2 =                            "1.3.132.0.7"
        case ansip160r1 =                           "1.3.132.0.8"
        case ansip160k1 =                           "1.3.132.0.9"
        case ansip256k1 =                           "1.3.132.0.10"
        case ansit163r2 =                           "1.3.132.0.15"
        case ansit283k1 =                           "1.3.132.0.16"
        case ansit283r1 =                           "1.3.132.0.17"
        case sect131r1 =                            "1.3.132.0.22"
        case sect131r2 =                            "1.3.132.0.23"
        case ansit193r1 =                           "1.3.132.0.24"
        case ansit193r2 =                           "1.3.132.0.25"
        case ansit233k1 =                           "1.3.132.0.26"
        case ansit233r1 =                           "1.3.132.0.27"
        case secp128r1 =                            "1.3.132.0.28"
        case secp128r2 =                            "1.3.132.0.29"
        case ansip160r2 =                           "1.3.132.0.30"
        case ansip192k1 =                           "1.3.132.0.31"
        case ansip224k1 =                           "1.3.132.0.32"
        case ansip224r1 =                           "1.3.132.0.33"
        case ansip384r1 =                           "1.3.132.0.34"
        case ansip521r1 =                           "1.3.132.0.35"
        case ansit409k1 =                           "1.3.132.0.36"
        case ansit409r1 =                           "1.3.132.0.37"
        case ansit571k1 =                           "1.3.132.0.38"
        case ansit571r1 =                           "1.3.132.0.39"
      }

      public enum schemes: OID, CaseIterable, OIDLeaf {
        public static let id: UInt64 = 1
        public static let names = ["schemes"]

        case dhSinglePassCofactorDHRecommendedKDF = "1.3.132.1.1"
        case dhSinglePassCofactorDHSpecifiedKDF =   "1.3.132.1.2"

        case ecdh =                                 "1.3.132.1.12"
        case ecmqv =                                "1.3.132.1.13"
      }
    }

  }
}
