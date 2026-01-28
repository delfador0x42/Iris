// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "IrisSatellite",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "IrisSatellite", targets: ["IrisSatellite"]),
    ],
    dependencies: [
        .package(path: "../IrisShared"),
    ],
    targets: [
        .target(
            name: "IrisSatellite",
            dependencies: [
                .product(name: "IrisShared", package: "IrisShared"),
            ],
            path: "Sources/IrisSatellite"
        ),
    ]
)
