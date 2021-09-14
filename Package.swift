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
    .package(url: "https://github.com/outfoxx/PotentCodables.git", from: "2.0.0"),
    .package(url: "https://github.com/sharplet/Regex.git", from: "2.1.0"),
    .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
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
      dependencies: ["ShieldOID"]
    ),
    .target(
      name: "ShieldPKCS",
      dependencies: ["ShieldX500"]
    ),
    .target(
      name: "ShieldX509",
      dependencies: ["ShieldX500", "ShieldPKCS", "BigInt"]
    ),
    .target(
      name: "ShieldCrypto"
    ),
    .target(
      name: "ShieldSecurity",
      dependencies: ["ShieldX509", "Regex"]
    ),
    .testTarget(
      name: "ShieldTests",
      dependencies: ["Shield"],
      path: "Tests"
    ),
  ]
)
