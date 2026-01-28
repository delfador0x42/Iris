// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "IrisDisk",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "IrisDisk", targets: ["IrisDisk"]),
    ],
    dependencies: [
        .package(path: "../IrisShared"),
    ],
    targets: [
        .target(
            name: "IrisDisk",
            dependencies: [
                .product(name: "IrisShared", package: "IrisShared"),
            ],
            path: "Sources/IrisDisk"
        ),
    ]
)
