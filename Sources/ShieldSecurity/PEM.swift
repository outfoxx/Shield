//
//  PEM.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import Regex

public enum PEM {

  public struct Kind: RawRepresentable {

    public var rawValue: String

    public init(rawValue: String) {
      self.rawValue = rawValue
    }

    public static let certificate = Self(rawValue: "CERTIFICATE")
    public static let pkcs8PrivateKey = Self(rawValue: "PRIVATE KEY")

  }

  private static let pemRegex =
    Regex(#"-----BEGIN ([\w\s]+)-----\s*([a-zA-Z0-9\s/+]+=*)\s*-----END \1-----"#)
  private static let pemWhitespaceRegex = Regex(#"[\n\t\s]+"#)

  public static func read(pem: String) -> [(Kind, Data)] {

    pemRegex.allMatches(in: pem)
      .compactMap { match in

        guard
          let kindCapture = match.captures.first,
          let kind = kindCapture,
          let dataCapture = match.captures.last,
          let base64Data = dataCapture?.replacingAll(matching: pemWhitespaceRegex, with: ""),
          let data = Data(base64Encoded: base64Data)
        else {
          return nil
        }

        return (.init(rawValue: kind), data)
      }

  }

  public static func write(kind: Kind, data: Data) -> String {
    let pem = data.base64EncodedString().chunks(ofCount: 64).joined(separator: "\n")
    return "-----BEGIN \(kind.rawValue)-----\n\(pem)\n-----END \(kind.rawValue)-----"
  }

}
