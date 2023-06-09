// swift-tools-version:5.4

import PackageDescription

let package = Package(
  name: "Shield",
  platforms: [
    .iOS(.v14),
    .macOS(.v11),
    .watchOS(.v7),
    .tvOS(.v14),
  ],
  products: [
    .library(
      name: "Shield",
      targets: ["Shield", "ShieldSecurity", "ShieldCrypto", "ShieldOID", "ShieldPKCS", "ShieldX509", "ShieldX500"]),
  ],
  dependencies: [
    .package(url: "https://github.com/outfoxx/PotentCodables.git", from: "3.0.0"),
    .package(url: "https://github.com/sharplet/Regex.git", from: "2.1.0"),
    .package(name: "Algorithms", url: "https://github.com/apple/swift-algorithms", from: "1.0.0"),
  ],
  targets: [
    .target(
      name: "Shield",
      dependencies: ["ShieldSecurity", "ShieldCrypto", "ShieldOID", "ShieldPKCS", "ShieldX509", "ShieldX500"],
      resources: [
        .process("Shield.docc")
      ]
    ),
    .target(
      name: "ShieldOID",
      dependencies: ["PotentCodables"]
    ),
    .target(
      name: "ShieldX500",
      dependencies: ["ShieldOID", "PotentCodables"]
    ),
    .target(
      name: "ShieldPKCS",
      dependencies: ["ShieldX509", "PotentCodables"]
    ),
    .target(
      name: "ShieldX509",
      dependencies: ["ShieldCrypto", "ShieldX500", "ShieldOID", "PotentCodables", "Algorithms"]
    ),
    .target(
      name: "ShieldCrypto"
    ),
    .target(
      name: "ShieldSecurity",
      dependencies: ["ShieldCrypto", "ShieldOID", "ShieldPKCS", "ShieldX500", "ShieldX509", "PotentCodables", "Regex"]
    ),
    .testTarget(
      name: "ShieldTests",
      dependencies: ["Shield"],
      path: "Tests"
    ),
  ]
)

#if swift(>=5.6)

package.dependencies.append(
  .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.1.0")
)

#endif
