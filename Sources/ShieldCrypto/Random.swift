//
//  Random.swift
//  
//
//  Created by Kevin Wooten on 7/11/19.
//

import Foundation
import CommonCrypto.Random


public struct Random {

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
