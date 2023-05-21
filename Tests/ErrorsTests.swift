//
//  ErrorsTests.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation
@testable import ShieldSecurity
import XCTest

class ErrorsTests: XCTestCase {

  func testCFErrorHumanReadable() {

    let error = CFErrorCreate(nil, "TestErrorDomain" as CFString, -1234, [
      kCFErrorLocalizedDescriptionKey: "An Error Occurred" as CFString,
      kCFErrorLocalizedFailureReasonKey: "Invalid Parameters" as CFString,
      kCFErrorLocalizedRecoverySuggestionKey: "Pass valid parameters" as CFString,
      kCFErrorUnderlyingErrorKey: CFErrorCreate(nil, kCFErrorDomainPOSIX, 1, nil)!,
    ] as [CFString: Any] as CFDictionary)!

    XCTAssertEqual(
      error.humanReadableDescription,
      """
      Code: -1234
      Domain: TestErrorDomain
      Description: An Error Occurred
      Failure Reason: Invalid Parameters
      Recovery Suggestion: Pass valid parameters
      Underlying Error:
        Code: 1
        Domain: NSPOSIXErrorDomain
        Description: The operation couldn’t be completed. Operation not permitted
        Failure Reason: Operation not permitted
      """
    )
  }

  @available(macOS 11.3, iOS 14.5, watchOS 7.4, tvOS 14.5, *)
  func testNSErrorHumanReadable() {

    let error = NSError(domain: "TestErrorDomain", code: -1234, userInfo: [
      kCFErrorLocalizedDescriptionKey: "An Error Occurred" as CFString,
      kCFErrorLocalizedFailureReasonKey: "Invalid Parameters" as CFString,
      kCFErrorLocalizedRecoverySuggestionKey: "Pass valid parameters" as CFString,
      NSLocalizedRecoveryOptionsErrorKey as CFString: [
        "Parameter 1 must be a string",
        "Parameter 2 must be a boolean",
      ],
      kCFErrorUnderlyingErrorKey: POSIXError(.EPERM),
      NSMultipleUnderlyingErrorsKey as CFString: [POSIXError(.EPERM), POSIXError(.ENOENT)],
    ] as [String: Any])

    XCTAssertEqual(
      error.humanReadableDescription,
      """
      Code: -1234
      Domain: TestErrorDomain
      Description: An Error Occurred
      Failure Reason: Invalid Parameters
      Recovery Suggestion: Pass valid parameters
      Recovery Options:
        Option 0: Parameter 1 must be a string
        Option 1: Parameter 2 must be a boolean
      Underlying Error:
        Code: 1
        Domain: NSPOSIXErrorDomain
        Description: The operation couldn’t be completed. Operation not permitted
        Failure Reason: Operation not permitted
      Underlying Errors:
        Error 0:
          Code: 1
          Domain: NSPOSIXErrorDomain
          Description: The operation couldn’t be completed. Operation not permitted
          Failure Reason: Operation not permitted
        Error 1:
          Code: 2
          Domain: NSPOSIXErrorDomain
          Description: The operation couldn’t be completed. No such file or directory
          Failure Reason: No such file or directory
      """
    )
  }
}
