//
//  DistinguishedNameStringParser.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldOID


public struct DistinguishedNameStringParser<Mapper: AttributeValueMapper> {

  public enum Error: Swift.Error {
    case badFormat(String)
  }

  typealias ATV = AttributeTypeAndValue<Mapper>

  public let style: NamingStyle
  public let separators: String

  public init(style: NamingStyle = .rfc4519, separators: String = ",") {
    self.style = style
    self.separators = separators
  }

  public func parse(string: String) throws -> RDNSequence<Mapper> {

    var tokenizer = Tokenizer(string: string, separators: separators)

    var rdns = [[ATV]]()

    while let token = tokenizer.nextToken() {

      var rdn = [ATV]()

      var seqTokenizer = Tokenizer(string: token, separators: "+")
      while let elementToken = seqTokenizer.nextToken() {

        var typeValueTokenizer = Tokenizer(string: elementToken, separators: "=")

        guard let typeToken = typeValueTokenizer.nextToken() else {
          throw Error.badFormat("Expected type token")
        }
        guard let valueToken = typeValueTokenizer.nextToken() else {
          throw Error.badFormat("Expected value token")
        }

        guard let type = style.oid(fromName: typeToken.trimmingCharacters(in: .whitespaces)) else {
          throw Error.badFormat("Unrecognized type value")
        }

        let value = unescape(valueToken)

        rdn.append(ATV(type: type, value: AnyString(value)))
      }

      rdns.append(rdn)
    }

    return rdns
  }

  private func unescape(_ string: String) -> String {

    if string.isEmpty || (!string.contains("\\") && !string.contains("\"")) {
      return string.trimmingCharacters(in: .whitespaces)
    }

    var currentIndex = string.startIndex
    let endIndex = string.endIndex
    var lastEscape: String.Index?
    var escaping = false
    var quoting = false
    var result = ""

    if string[currentIndex] == "\\" {
      // starting escaped

      let nextIndex = string.index(after: currentIndex)

      // is it an escaped hash string?
      if nextIndex != endIndex, string[nextIndex] == "#" {
        // preserve escaping
        currentIndex = string.index(after: nextIndex)
        result.append("\\#")
      }
    }

    var nonWhitespace = false

    while currentIndex != endIndex {

      let current = string[currentIndex]

      nonWhitespace = nonWhitespace || current != " "

      if current == "\"" {
        // treat as control?
        if !escaping {
          // start or stop quoting
          quoting = !quoting
        }
        else {
          result.append(current)
          escaping = false
        }
      }
      else if current == "\\", !escaping, !quoting {
        escaping = true
        lastEscape = result.endIndex
      }
      else {

        if current == " ", !escaping, !nonWhitespace {
          currentIndex = string.index(after: currentIndex)
          continue
        }

        if escaping, let hexDigit1 = current.hexDigitValue {
          currentIndex = string.index(after: currentIndex)
          guard currentIndex != endIndex, let hexDigit2 = string[currentIndex].hexDigitValue else {
            fatalError()
          }

          let char = Character(UnicodeScalar(hexDigit1 * 16 + hexDigit2)!)
          result.append(char)
        }
        else {
          result.append(current)
        }

        escaping = false
      }

      currentIndex = string.index(after: currentIndex)
    }

    if !result.isEmpty {
      while
        let lastIndex = result.index(result.endIndex, offsetBy: -1, limitedBy: result.startIndex),
        result[lastIndex] == " ", lastIndex != lastEscape {
        result.removeLast()
      }
    }

    return result
  }

  struct Tokenizer {

    var string: String
    var currentIndex: String.Index
    var separators: String

    init(string: String, separators: String) {
      self.string = string
      currentIndex = string.startIndex
      self.separators = separators
    }

    mutating func peek() -> Character {
      return string[currentIndex]
    }

    mutating func pop() -> Character {
      defer { currentIndex = string.index(after: currentIndex) }
      return peek()
    }

    var hasTokens: Bool { currentIndex != string.endIndex }

    mutating func nextToken() -> String? {
      guard hasTokens else { return nil }

      var quoting = false
      var escaping = false
      var token = ""

      while currentIndex != string.endIndex {
        let current = string[currentIndex]

        if current == "\"" {
          // treat as control?
          if !escaping {
            // start or stop quoting
            quoting = !quoting
          }

          token.append(current)
          escaping = false
        }
        else {

          if escaping || quoting {
            token.append(current)
            escaping = false
          }
          else if current == "\\" {
            token.append(current)
            escaping = true
          }
          else if separators.contains(current) {
            break
          }
          else {
            token.append(current)
          }

        }

        currentIndex = string.index(after: currentIndex)
      }

      currentIndex = string.index(currentIndex, offsetBy: 1, limitedBy: string.endIndex) ?? string.endIndex

      return token
    }

  }

}
