// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "IrisShared",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "IrisShared", targets: ["IrisShared"]),
    ],
    targets: [
        .target(
            name: "IrisShared",
            path: "Sources/IrisShared"
        ),
    ]
)
