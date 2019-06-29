//
//  DigestTests.swift
//  CryptoSecurity
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

@testable import Shield
import XCTest


class DigestTests: XCTestCase {


  let data = try! Random.generate(count: 3619)


  func exec(_ digester: AnyDigester) throws -> Data {
    var digester = digester

    var data = self.data

    while data.count > 0 {

      let amt = min(data.count, 33)

      digester.update(data: data.subdata(in: 0 ..< amt))

      data = data.subdata(in: amt ..< data.count)
    }

    return digester.final()
  }

  func testDigestBlocksMD2() throws {

    let blocksDigest = try exec(Digester.for(.md2))

    XCTAssertEqual(blocksDigest, Digester.digest(data, using: .md2))
  }

  func testDigestBlocksMD4() throws {

    let blocksDigest = try exec(Digester.for(.md4))

    XCTAssertEqual(blocksDigest, Digester.digest(data, using: .md4))
  }

  func testDigestBlocksMD5() throws {

    let blocksDigest = try exec(Digester.for(.md5))

    XCTAssertEqual(blocksDigest, Digester.digest(data, using: .md5))
  }

  func testDigestBlocksSHA1() throws {

    let blocksDigest = try exec(Digester.for(.sha1))

    XCTAssertEqual(blocksDigest, Digester.digest(data, using: .sha1))
  }

  func testDigestBlocksSHA224() throws {

    let blocksDigest = try exec(Digester.for(.sha224))

    XCTAssertEqual(blocksDigest, Digester.digest(data, using: .sha224))
  }

  func testDigestBlocksSHA256() throws {

    let blocksDigest = try exec(Digester.for(.sha256))

    XCTAssertEqual(blocksDigest, Digester.digest(data, using: .sha256))
  }

  func testDigestBlocksSHA384() throws {

    let blocksDigest = try exec(Digester.for(.sha384))

    XCTAssertEqual(blocksDigest, Digester.digest(data, using: .sha384))
  }

  func testDigestBlocksSHA512() throws {

    let blocksDigest = try exec(Digester.for(.sha512))

    XCTAssertEqual(blocksDigest, Digester.digest(data, using: .sha512))
  }

}
