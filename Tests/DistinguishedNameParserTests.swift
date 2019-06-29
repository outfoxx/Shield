//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/24/19.
//

import Foundation
import ShieldX509
import ShieldOID
import PotentASN1
import XCTest


class DistinguishedNameParserTests: XCTestCase {

  func testParseBasic1() throws {

    let built = NameBuilder()
      .add("AU", forType: iso_itu.ds.attributeType.countryName.oid)
      .add("Victoria", forType: iso_itu.ds.attributeType.stateOrProvinceName.oid)
      .add("South Melbourne", forType: iso_itu.ds.attributeType.localityName.oid)
      .add("Connect 4 Pty Ltd", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("Webserver Team", forType: iso_itu.ds.attributeType.organizationalUnitName.oid)
      .add("www2.connect4.com.au", forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let parsed = try NameBuilder.parse(string: "C=AU,ST=Victoria,L=South Melbourne,O=Connect 4 Pty Ltd,OU=Webserver Team,CN=www2.connect4.com.au")
    XCTAssertEqual(built, parsed)
  }

  func testParseBasic2() throws {

    let built = NameBuilder()
      .add("AU", forType: iso_itu.ds.attributeType.countryName.oid)
      .add("QLD", forType: iso_itu.ds.attributeType.stateOrProvinceName.oid)
      .add("SSLeay/rsa test cert", forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let parsed = try NameBuilder.parse(string: "C=AU,ST=QLD,CN=SSLeay/rsa test cert")
    XCTAssertEqual(built, parsed)
  }

  func testParseBasic3() throws {

    let built = NameBuilder()
      .add("US", forType: iso_itu.ds.attributeType.countryName.oid)
      .add("Hewlett Packard Company (ISSL)", forType: iso_itu.ds.attributeType.organizationalUnitName.oid)
      .add("Paul A. Cooke", forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let parsed = try NameBuilder.parse(string: "C=US,OU=Hewlett Packard Company (ISSL),CN=Paul A. Cooke")
    XCTAssertEqual(built, parsed)
  }

  func testParseEscaped1() throws {

    let built = NameBuilder()
      .add("*.canal-plus.com", forType: iso_itu.ds.attributeType.commonName.oid)
      .add("Provided by TBS INTERNET http://www.tbs-certificats.com/", forType: iso_itu.ds.attributeType.organizationalUnitName.oid)
      .add(" CANAL +", forType: iso_itu.ds.attributeType.organizationalUnitName.oid)
      .add("CANAL+DISTRIBUTION", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("issy les moulineaux", forType:  iso_itu.ds.attributeType.localityName.oid)
      .add("Hauts de Seine", forType: iso_itu.ds.attributeType.stateOrProvinceName.oid)
      .add("FR", forType: iso_itu.ds.attributeType.countryName.oid)
      .name
    let parsed = try NameBuilder.parse(string: #"CN=*.canal-plus.com,OU=Provided by TBS INTERNET http://www.tbs-certificats.com/,OU=\ CANAL \+,O=CANAL\+DISTRIBUTION,L=issy les moulineaux,ST=Hauts de Seine,C=FR"#)
    XCTAssertEqual(built, parsed)
  }

  func testParseEscaped2() throws {

    let built = NameBuilder()
      .add("Shield", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add(#"c:\fred\bob"#, forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let parsed = try NameBuilder.parse(string: #"O=Shield,CN=c:\\fred\\bob"#)
    XCTAssertEqual(built, parsed)

  }

  func testParseEscaped3() throws {

    let built = NameBuilder()
      .add("Shield", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("github.com/outfoxx/shield ", forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let parsed = try NameBuilder.parse(string: #"O=Shield,CN=github.com/outfoxx/shield\ "#)
    XCTAssertEqual(built, parsed)

  }

  func testParseMultiValued() throws {

    let built = NameBuilder()
      .add("US", forType: iso_itu.ds.attributeType.countryName.oid)
      .add("National Aeronautics and Space Administration", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add(multiValued: (iso_itu.ds.attributeType.serialNumber.oid, "16"), (iso_itu.ds.attributeType.commonName.oid, "Steve Schoch"))
      .name
    let parsed = try NameBuilder.parse(string: "C=US,O=National Aeronautics and Space Administration,SERIALNUMBER=16+CN=Steve Schoch")
    XCTAssertEqual(built, parsed)
  }

  func testParseHex1() throws {
    let built = NameBuilder()
      .add(" Test X", forType: iso_itu.ds.attributeType.commonName.oid)
      .add(" Test", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("GB", forType: iso_itu.ds.attributeType.countryName.oid)
      .name
    let parsed = try NameBuilder.parse(string: "CN=\\20Test\\20X,O=\\20Test,C=GB")
    XCTAssertEqual(built, parsed)
  }

  func testParseHex2() throws {
    let built = NameBuilder()
      .add(" Test X ", forType: iso_itu.ds.attributeType.commonName.oid)
      .add(" Test", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("GB", forType: iso_itu.ds.attributeType.countryName.oid)
      .name
    let parsed = try NameBuilder.parse(string: #"CN=\20Test\20X\20,O=\20Test,C=GB"#)
    XCTAssertEqual(built, parsed)
    let parsed2 = try NameBuilder.parse(string: #"CN=\20Test\20X\20    ,O=\20Test,C=GB"#)
    XCTAssertEqual(built, parsed2)
  }

  func testParseHex3() throws {
    let built = NameBuilder()
      .add(#" Test X    "#, forType: iso_itu.ds.attributeType.commonName.oid)
      .add(" Test", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("GB", forType: iso_itu.ds.attributeType.countryName.oid)
      .name
    let parsed = try NameBuilder.parse(string: #"CN=\20Test\20X\20  \20  ,O=\20Test,C=GB"#)
    XCTAssertEqual(built, parsed)
  }

  func testParseHex4() throws {
    let built = NameBuilder()
      .add(#" "#, forType: iso_itu.ds.attributeType.commonName.oid)
      .add(" Test", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("GB", forType: iso_itu.ds.attributeType.countryName.oid)
      .name
    let parsed = try NameBuilder.parse(string: #"CN=\20,O=\20Test,C=GB"#)
    XCTAssertEqual(built, parsed)
  }

  func testParseHex5() throws {
    let built = NameBuilder()
      .add(#" "#, forType: iso_itu.ds.attributeType.commonName.oid)
      .add(" Test", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("GB", forType: iso_itu.ds.attributeType.countryName.oid)
      .name
    let parsed = try NameBuilder.parse(string: #"CN=\20,O=\20Test,C=GB"#)
    XCTAssertEqual(built, parsed)
    let parsed2 = try NameBuilder.parse(string: #"CN=\ ,O=\20Test,C=GB"#)
    XCTAssertEqual(built, parsed2)
  }

}
