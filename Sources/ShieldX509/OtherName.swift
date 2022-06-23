//
//  OtherName.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1


public struct OtherName: Equatable, Hashable, Codable {
  public var typeId: ObjectIdentifier
  public var value: ASN1

  public init(typeId: ObjectIdentifier, value: ASN1) {
    self.typeId = typeId
    self.value = value
  }

  enum CodingKeys: CodingKey {
    case typeId
    case value
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    self.typeId = try container.decode(ObjectIdentifier.self, forKey: .typeId)
    let value = try container.decode(ASN1.self, forKey: .value)
    guard case let ASN1.tagged(_, data) = value else {
      throw DecodingError.dataCorruptedError(forKey: .value, in: container, debugDescription: "Expected tagged value")
    }
    self.value = try DERReader.parse(data: data).first ?? .null
  }

  public func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(typeId, forKey: .typeId)
    try container.encode(ASN1.tagged(ASN1.Tag.tag(from: 0, in: .contextSpecific, constructed: true), DERWriter.write(value)), forKey: .value)
  }

}



// MARK: Schemas

public extension Schemas {

  static let OtherName: Schema =
    .sequence([
      "typeId": .type(.objectIdentifier()),
      "value": .explicit(0, in: .contextSpecific, .dynamic([:])),
    ])

}
