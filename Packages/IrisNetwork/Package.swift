// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "IrisNetwork",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "IrisNetwork", targets: ["IrisNetwork"]),
    ],
    dependencies: [
        .package(path: "../IrisShared"),
    ],
    targets: [
        .target(
            name: "IrisNetwork",
            dependencies: [
                .product(name: "IrisShared", package: "IrisShared"),
            ],
            path: "Sources/IrisNetwork"
        ),
    ]
)
