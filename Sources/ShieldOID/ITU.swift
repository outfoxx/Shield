//
//  ITU.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1

// swiftformat:disable consecutiveSpaces

/// International Telecommunication Union - Telecommunication standardization sector (ITU-T)
///
/// See: http://oid-info.com/get/0
///
public struct itu: OIDBranch {
  public static let id: UInt64 = 0
  public static let names = ["itu"]
  internal static let children: [OIDNode.Type] = [data.self]

  public struct data: OIDBranch {
    public static let id: UInt64 = 9
    public static let names = ["data"]
    internal static let children: [OIDNode.Type] = [pss.self]

    public struct pss: OIDBranch {
      public static let id: UInt64 = 2342
      public static let names = ["pss"]
      internal static let children: [OIDNode.Type] = [ucl.self]

      public struct ucl: OIDBranch {
        public static let id: UInt64 = 19200300
        public static let names = ["ucl"]
        internal static let children: [OIDNode.Type] = [pilot.self]

        public struct pilot: OIDBranch {
          public static let id: UInt64 = 100
          public static let names = ["pilot"]
          internal static let children: [OIDNode.Type] = [pilotAttributeType.self]

          public enum pilotAttributeType: OID, CaseIterable, OIDLeaf {
            public static let id: UInt64 = 1
            public static let names = ["pilotAttributeType"]
            private static let children: [OIDNode.Type] = []

            case userId =                           "0.9.2342.19200300.100.1.1"
            case domainComponent =                  "0.9.2342.19200300.100.1.25"
          }
        }
      }
    }
  }
}
