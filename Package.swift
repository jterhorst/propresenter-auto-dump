// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "ProPresenterProtos",
    products: [
        .library(name: "ProPresenterProtos", targets: ["ProPresenterProtos"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.28.0"),
    ],
    targets: [
        .target(
            name: "ProPresenterProtos",
            dependencies: [
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            path: "swift"
        ),
        .testTarget(
            name: "ProPresenterProtosTests",
            dependencies: [
                "ProPresenterProtos",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ],
            path: "Tests/ProPresenterProtosTests"
        ),
    ]
)
