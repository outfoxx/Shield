//
//  Name.swift
//  Shield
//
//  Copyright © 2019 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
import PotentASN1
import ShieldX500


public typealias Name = RDNSequence<DirectoryNameAttributeMapper>

public typealias NameBuilder = DistinguishedNameBuilder<DirectoryNameAttributeMapper>

public extension NameBuilder {

  var name: RDNSequence<Mapper> { rdns }

}

public typealias NameStringComposer = DistinguishedNameStringComposer<DirectoryNameAttributeMapper>



// MARK: Schemas

public extension Schemas {

  static let Name: Schema =
    .choiceOf([
      ShieldX500.Schemas.rdnSequence(DirectoryNames, unknownTypeSchema: directoryString()),
    ])

}
