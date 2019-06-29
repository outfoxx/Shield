//
//  HmacTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


class HmacTests: XCTestCase {

  let key = "secret".data(using: .utf8)!
  let data = try! Random.generate(count: 3619)

  func exec(_ hmac: HMAC) -> Data {
    var hmac = hmac

    var data = self.data

    while data.count > 0 {

      let amt = min(data.count, 33)

      hmac.update(data: data.subdata(in: 0 ..< amt))

      data = data.subdata(in: amt ..< data.count)
    }

    return hmac.final()
  }

  func testHmacBlocksSHA1() throws {

    let blocksMac = exec(HMAC(.sha1, key: key))

    XCTAssertEqual(blocksMac, HMAC.hmac(data, using: .sha1, key: key))
  }

  func testDigestBlocksSHA224() throws {

    let blocksMac = exec(HMAC(.sha224, key: key))

    XCTAssertEqual(blocksMac, HMAC.hmac(data, using: .sha224, key: key))
  }

  func testDigestBlocksSHA256() throws {

    let blocksMac = exec(HMAC(.sha256, key: key))

    XCTAssertEqual(blocksMac, HMAC.hmac(data, using: .sha256, key: key))
  }

  func testDigestBlocksSHA384() throws {

    let blocksMac = exec(HMAC(.sha384, key: key))

    XCTAssertEqual(blocksMac, HMAC.hmac(data, using: .sha384, key: key))
  }

  func testDigestBlocksSHA512() throws {

    let blocksMac = exec(HMAC(.sha512, key: key))

    XCTAssertEqual(blocksMac, HMAC.hmac(data, using: .sha512, key: key))
  }

}
