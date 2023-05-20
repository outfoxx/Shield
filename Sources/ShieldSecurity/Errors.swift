//
//  Errors.swift
//  Shield
//
//  Copyright © 2021 Outfox, inc.
//
//
//  Distributed under the MIT License, See LICENSE for details.
//

import Foundation

extension CFError {

  var humanReadableDescription: String {
    humanReadableDescriptionLines.joined(separator: "\n")
  }

  var humanReadableDescriptionLines: [String] {

    guard let userInfo = CFErrorCopyUserInfo(self) as? [CFString: Any] else {
      return [CFErrorCopyDescription(self) as String]
    }

    var lines: [String] = []

    lines += [
      "Code: \(CFErrorGetCode(self))",
      "Domain: \(CFErrorGetDomain(self)!)",
    ]

    if let localizedErrorDesc = userInfo[kCFErrorLocalizedDescriptionKey] {
      lines.append("Description: \(localizedErrorDesc)")
    }

    if let localizedFailureReasonDesc = userInfo[kCFErrorLocalizedFailureReasonKey] {
      lines.append("Failure Reason: \(localizedFailureReasonDesc)")
    }

    if let localizedRecoverySuggestion = userInfo[kCFErrorLocalizedRecoverySuggestionKey] {
      lines.append("Recovery Suggestion: \(localizedRecoverySuggestion)")
    }

    if let underlyingError = userInfo[kCFErrorUnderlyingErrorKey] {
      lines += describe(title: "Underlying Error", error: underlyingError)
    }

    return lines
  }

}

extension NSError {

  var humanReadableDescription: String {
    humanReadableDescriptionLines.joined(separator: "\n")
  }

  var humanReadableDescriptionLines: [String] {

    var lines: [String] = []

    lines += [
      "Code: \(code)",
      "Domain: \(domain)",
      "Description: \(localizedDescription)",
    ]

    if let localizedFailureReason {
      lines.append("Failure Reason: \(localizedFailureReason)")
    }

    if let localizedRecoverySuggestion {
      lines.append("Recovery Suggestion: \(localizedRecoverySuggestion)")
    }

    if let localizedRecoveryOptions {
      lines += ["Recovery Options:"] + localizedRecoveryOptions.enumerated().map { idx, option in
        "  Option \(idx): \(option)"
      }
    }

    if let underlyingError = userInfo[NSUnderlyingErrorKey] as? NSError {
      lines += describe(title: "Underlying Error", error: underlyingError)
    }

    if #available(macOS 11.3, iOS 14.5, watchOS 7.4, tvOS 14.5, *) {

      if let underlyingErrors = userInfo[NSMultipleUnderlyingErrorsKey] as? NSError {
        lines += ["Underlying Errors:"] + describe(title: "Error 0", error: underlyingErrors)
      }

      if let underlyignErrors = userInfo[NSMultipleUnderlyingErrorsKey] as? NSArray {
        lines += ["Underlying Errors:"] + underlyignErrors.enumerated().flatMap { idx, error in
          return describe(title: "Error \(idx)", error: error)
        }.map { "  \($0)" }
      }

    }

    return lines
  }

}

private func describe(title: String, error: Any) -> [String] {
  if let error = error as? NSError {
    return ["\(title):"] + error.humanReadableDescriptionLines.map { "  \($0)" }
  }
  else {
    let error = error as! CFError // swiftlint:disable:this force_cast
    return ["\(title):"] + error.humanReadableDescriptionLines.map { "  \($0)" }
  }
}
