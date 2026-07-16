import AuthKit
import Foundation

let exitCode = await CLI().run(
    arguments: Array(CommandLine.arguments.dropFirst()),
    environment: ProcessInfo.processInfo.environment
)
exit(exitCode)
