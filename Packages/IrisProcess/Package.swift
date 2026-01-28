// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "IrisProcess",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "IrisProcess", targets: ["IrisProcess"]),
    ],
    dependencies: [
        .package(path: "../IrisShared"),
    ],
    targets: [
        .target(
            name: "IrisProcess",
            dependencies: [
                .product(name: "IrisShared", package: "IrisShared"),
            ],
            path: "Sources/IrisProcess"
        ),
    ]
)
