// swift-tools-version:5.0

import PackageDescription

let package = Package(
  name: "Shield",
  platforms: [
    .iOS("10.0"),
    .macOS("10.12"),
    .watchOS("3.0"),
    .tvOS("10.0"),
  ],
  products: [
    .library(
      name: "Shield",
      targets: ["Shield", "ShieldSecurity", "ShieldCrypto", "ShieldOID", "ShieldPKCS", "ShieldX509", "ShieldX500"]),
  ],
  dependencies: [
    .package(url: "https://github.com/outfoxx/PotentCodables.git", from: "2.3.0"),
    .package(url: "https://github.com/sharplet/Regex.git", from: "2.1.0")
  ],
  targets: [
    .target(
      name: "Shield",
      dependencies: ["ShieldSecurity", "ShieldCrypto", "ShieldOID", "ShieldPKCS", "ShieldX509", "ShieldX500"]
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
      dependencies: ["ShieldX500", "PotentCodables"]
    ),
    .target(
      name: "ShieldX509",
      dependencies: ["ShieldCrypto", "ShieldX500", "ShieldOID", "ShieldPKCS", "PotentCodables"]
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
