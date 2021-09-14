//
//  Random.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import CommonCrypto.Random
import Foundation


public enum Random {

  public static func generate(count: Int) throws -> Data {
    var data = Data(repeating: 0, count: count)
    try data.withUnsafeMutableBytes { ptr in
      let status = CCRandomGenerateBytes(ptr.baseAddress!, ptr.count)
      if status != kCCSuccess {
        throw CCError(rawValue: status)
      }
    }
    return data

  }

}
