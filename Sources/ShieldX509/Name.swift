//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/24/19.
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
      ShieldX500.Schemas.RDNSequence(DirectoryNames, allowUnknownTypes: true)
    ])

}
