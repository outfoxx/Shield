//
//  Logger.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import OSLog

private var defaultLogger = Logger()

extension Logger {

  static var `default`: Logger { defaultLogger }

}
