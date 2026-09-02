// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "manifest-poc",
    platforms: [.macOS("15.0")],
    dependencies: [
        // Pin this to the commit/tag you're validating the report against.
        .package(url: "https://github.com/apple/containerization.git", branch: "main"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .executableTarget(
            name: "manifest-poc",
            dependencies: [
                .product(name: "Containerization", package: "containerization"),
                .product(name: "ContainerizationOCI", package: "containerization"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        )
    ]
)
