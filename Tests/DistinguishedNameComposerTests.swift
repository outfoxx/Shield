//
//  DistinguishedNameComposerTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldOID
import ShieldX509
import XCTest


class DistinguishedNameComposerTests: XCTestCase {

  func testComposeBasic1() throws {

    let built = NameBuilder()
      .add("AU", forType: iso_itu.ds.attributeType.countryName.oid)
      .add("Victoria", forType: iso_itu.ds.attributeType.stateOrProvinceName.oid)
      .add("South Melbourne", forType: iso_itu.ds.attributeType.localityName.oid)
      .add("Connect 4 Pty Ltd", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("Webserver Team", forType: iso_itu.ds.attributeType.organizationalUnitName.oid)
      .add("www2.connect4.com.au", forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let composed = try NameStringComposer.compose(built)
    XCTAssertEqual(
      composed,
      "c=AU,st=Victoria,l=South Melbourne,o=Connect 4 Pty Ltd,ou=Webserver Team,cn=www2.connect4.com.au"
    )
  }

  func testComposeBasic2() throws {

    let built = NameBuilder()
      .add("AU", forType: iso_itu.ds.attributeType.countryName.oid)
      .add("QLD", forType: iso_itu.ds.attributeType.stateOrProvinceName.oid)
      .add("SSLeay/rsa test cert", forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let composed = try NameStringComposer.compose(built)
    XCTAssertEqual(composed, "c=AU,st=QLD,cn=SSLeay/rsa test cert")
  }

  func testComposeBasic3() throws {

    let built = NameBuilder()
      .add("US", forType: iso_itu.ds.attributeType.countryName.oid)
      .add("Hewlett Packard Company (ISSL)", forType: iso_itu.ds.attributeType.organizationalUnitName.oid)
      .add("Paul A. Cooke", forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let composed = try NameStringComposer.compose(built)
    XCTAssertEqual(composed, "c=US,ou=Hewlett Packard Company (ISSL),cn=Paul A. Cooke")
  }

  func testComposeEscaped1() throws {

    let built = NameBuilder()
      .add("*.canal-plus.com", forType: iso_itu.ds.attributeType.commonName.oid)
      .add(
        "Provided by TBS INTERNET http://www.tbs-certificats.com/",
        forType: iso_itu.ds.attributeType.organizationalUnitName.oid
      )
      .add(" CANAL +", forType: iso_itu.ds.attributeType.organizationalUnitName.oid)
      .add("CANAL+DISTRIBUTION", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("issy les moulineaux", forType: iso_itu.ds.attributeType.localityName.oid)
      .add("Hauts de Seine", forType: iso_itu.ds.attributeType.stateOrProvinceName.oid)
      .add("FR", forType: iso_itu.ds.attributeType.countryName.oid)
      .name
    let composed = try NameStringComposer.compose(built)
    XCTAssertEqual(
      composed,
      // swiftlint:disable:next line_length
      #"cn=*.canal-plus.com,ou=Provided by TBS INTERNET http://www.tbs-certificats.com/,ou=\ CANAL \+,o=CANAL\+DISTRIBUTION,l=issy les moulineaux,st=Hauts de Seine,c=FR"#
    )
  }

  func testComposeEscaped2() throws {

    let built = NameBuilder()
      .add("Shield", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add(#"c:\fred\bob"#, forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let composed = try NameStringComposer.compose(built)
    XCTAssertEqual(composed, #"o=Shield,cn=c:\\fred\\bob"#)

  }

  func testComposeEscaped3() throws {

    let built = NameBuilder()
      .add("Shield", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add("github.com/outfoxx/shield ", forType: iso_itu.ds.attributeType.commonName.oid)
      .name
    let composed = try NameStringComposer.compose(built)
    XCTAssertEqual(composed, #"o=Shield,cn=github.com/outfoxx/shield\ "#)

  }

  func testComposeMultiValued() throws {

    let built = NameBuilder()
      .add("US", forType: iso_itu.ds.attributeType.countryName.oid)
      .add("National Aeronautics and Space Administration", forType: iso_itu.ds.attributeType.organizationName.oid)
      .add(
        multiValued: (iso_itu.ds.attributeType.serialNumber.oid, "16"),
        (iso_itu.ds.attributeType.commonName.oid, "Steve Schoch")
      )
      .name
    let composed = try NameStringComposer.compose(built)
    XCTAssertEqual(composed, "c=US,o=National Aeronautics and Space Administration,serialNumber=16+cn=Steve Schoch")
  }

}
