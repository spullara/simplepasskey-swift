// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "SimplePasskey",
    platforms: [
        .iOS(.v16),
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "SimplePasskey",
            targets: ["SimplePasskey"]
        ),
    ],
    targets: [
        .target(name: "SimplePasskey"),
        .testTarget(
            name: "SimplePasskeyTests",
            dependencies: ["SimplePasskey"]
        ),
    ]
)