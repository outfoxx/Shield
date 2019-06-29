//
//  File.swift
//  
//
//  Created by Kevin Wooten on 7/11/19.
//

import XCTest


class ParameterizedTest: XCTestCase {

  override class var defaultTestSuite : XCTestSuite {
    let testClass = NSClassFromString(NSStringFromClass(self)) as! XCTestCase.Type
    let testSuite = XCTestSuite(forTestCaseClass: self)
    parameterSets.forEach { parameterSet in
      testInvocations.forEach { invocation in
        let testCase = testClass.init(invocation: invocation) as! ParameterizedTest
        testCase.setUp(with: parameterSet)
        testSuite.addTest(testCase)
      }
    }
    return testSuite
  }

  open class var parameterSets : [Any] {
    return []
  }

  open func setUp(with parameters: Any) {
  }

}
