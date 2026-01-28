// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "IrisApp",
    platforms: [
        .macOS(.v15)
    ],
    products: [
        .library(name: "IrisApp", targets: ["IrisApp"]),
    ],
    dependencies: [
        .package(path: "../IrisShared"),
        .package(path: "../IrisDisk"),
        .package(path: "../IrisProcess"),
        .package(path: "../IrisNetwork"),
        .package(path: "../IrisSatellite"),
    ],
    targets: [
        .target(
            name: "IrisApp",
            dependencies: [
                .product(name: "IrisShared", package: "IrisShared"),
                .product(name: "IrisDisk", package: "IrisDisk"),
                .product(name: "IrisProcess", package: "IrisProcess"),
                .product(name: "IrisNetwork", package: "IrisNetwork"),
                .product(name: "IrisSatellite", package: "IrisSatellite"),
            ],
            path: "Sources/IrisApp"
        ),
    ]
)
