//
//  Moved.swift
//
//
//  Created by Kevin Wooten on 6/8/23.
//

import ShieldX509
import PotentASN1

// The following types have been moved to ShieldX509 due to issues with circular references

public typealias RSAPrivateKey = ShieldX509.RSAPrivateKey
public typealias RSAPublicKey = ShieldX509.RSAPublicKey
public typealias ECParameters = ShieldX509.ECParameters

public extension Schemas {
  static let RSAPrivateKey = ShieldX509.Schemas.RSAPrivateKey
  static let RSAPrivateKeyOtherPrimeInfos = ShieldX509.Schemas.RSAPrivateKeyOtherPrimeInfos
  static let RSAPrivateKeyOtherPrimeInfo = ShieldX509.Schemas.RSAPrivateKeyOtherPrimeInfo
  static let RSAPublicKey = ShieldX509.Schemas.RSAPublicKey
  static let ECParameters = ShieldX509.Schemas.ECParameters
}
