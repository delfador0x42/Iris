// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "Iris",
    platforms: [
        .macOS(.v15)  // Metal 4 requires macOS 15 Sequoia
    ],
    products: [
        .executable(name: "Iris", targets: ["Iris"]),
    ],
    dependencies: [
        // Local feature packages
        .package(path: "Packages/IrisShared"),
        .package(path: "Packages/IrisDisk"),
        .package(path: "Packages/IrisProcess"),
        .package(path: "Packages/IrisNetwork"),
        .package(path: "Packages/IrisSatellite"),
        .package(path: "Packages/IrisApp"),
    ],
    targets: [
        // Main executable - entry point only
        .executableTarget(
            name: "Iris",
            dependencies: [
                .product(name: "IrisApp", package: "IrisApp"),
            ],
            path: "Sources/Iris"
        ),

        // MARK: - Test Targets

        .testTarget(
            name: "IrisSatelliteTests",
            dependencies: [
                .product(name: "IrisSatellite", package: "IrisSatellite"),
                .product(name: "IrisShared", package: "IrisShared"),
            ],
            path: "Tests/IrisSatelliteTests"
        ),

        .testTarget(
            name: "IrisSharedTests",
            dependencies: [
                .product(name: "IrisShared", package: "IrisShared"),
            ],
            path: "Tests/IrisSharedTests"
        ),

        .testTarget(
            name: "IrisNetworkTests",
            dependencies: [
                .product(name: "IrisNetwork", package: "IrisNetwork"),
                .product(name: "IrisShared", package: "IrisShared"),
            ],
            path: "Tests/IrisNetworkTests"
        ),

        .testTarget(
            name: "IrisProcessTests",
            dependencies: [
                .product(name: "IrisProcess", package: "IrisProcess"),
                .product(name: "IrisShared", package: "IrisShared"),
            ],
            path: "Tests/IrisProcessTests"
        ),
    ]
)
