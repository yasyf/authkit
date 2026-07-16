// swift-tools-version: 6.2
import PackageDescription

/// Logic lives in the AuthKit library; the executable target is a thin dispatch
/// shell. Tests import the library, never the executable.
///
/// macOS 13 is the floor: it matches cookiesync-keyhelper's LSMinimumSystemVersion
/// (13.0) and the cask's ventura requirement, and every Security/LocalAuthentication
/// API used here predates it. cc-sudo pins macOS 15 on its own side; 15 >= 13.
///
/// No dependencies on purpose: the 0/1/2/3 exit-code contract is a wire ABI shared
/// with the Go bridge, and an argument-parsing library's own exit codes (64 on
/// usage errors) would corrupt it.
let package = Package(
    name: "authkit",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "AuthKit", targets: ["AuthKit"]),
        .executable(name: "authkit", targets: ["authkit-cli"]),
    ],
    targets: [
        // The executable target is authkit-cli, not authkit: on a
        // case-insensitive filesystem an `authkit` module would collide with
        // `AuthKit` in both Sources/ and the build directory. The shipped
        // binary name comes from the product (and the .app bundle copy).
        .target(name: "AuthKit"),
        .executableTarget(name: "authkit-cli", dependencies: ["AuthKit"]),
        .testTarget(name: "AuthKitTests", dependencies: ["AuthKit"]),
    ]
)
