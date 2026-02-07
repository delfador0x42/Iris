import Foundation
import os.log

/// Enumerates installed packages from Homebrew, pkgutil, and /Applications
public actor PackageInventory {
    public static let shared = PackageInventory()

    private let logger = Logger(subsystem: "com.wudan.iris", category: "PackageInventory")

    /// Scan all package sources and return combined inventory
    public func scan() async -> [InstalledPackage] {
        async let brew = scanHomebrew()
        async let pkgs = scanPkgutil()
        async let apps = scanApplications()

        let results = await [brew, pkgs, apps]
        return results.flatMap { $0 }
    }

    // MARK: - Homebrew

    private func scanHomebrew() async -> [InstalledPackage] {
        let output = await runCommand("/opt/homebrew/bin/brew", args: ["list", "--versions"])
        guard !output.isEmpty else {
            // Try Intel path
            let intelOutput = await runCommand("/usr/local/bin/brew", args: ["list", "--versions"])
            return parseBrewOutput(intelOutput)
        }
        return parseBrewOutput(output)
    }

    private func parseBrewOutput(_ output: String) -> [InstalledPackage] {
        output.split(separator: "\n").compactMap { line in
            let parts = line.split(separator: " ", maxSplits: 1)
            guard let name = parts.first else { return nil }
            let version = parts.count > 1 ? String(parts[1]) : nil
            return InstalledPackage(
                name: String(name),
                version: version,
                source: .homebrew
            )
        }
    }

    // MARK: - pkgutil

    private func scanPkgutil() async -> [InstalledPackage] {
        let output = await runCommand("/usr/sbin/pkgutil", args: ["--pkgs"])
        return output.split(separator: "\n").compactMap { line in
            let pkgId = String(line).trimmingCharacters(in: .whitespacesAndNewlines)
            guard !pkgId.isEmpty else { return nil }
            let name = pkgId.components(separatedBy: ".").last ?? pkgId
            return InstalledPackage(
                name: name,
                source: .pkgutil,
                bundleId: pkgId
            )
        }
    }

    // MARK: - Applications

    private func scanApplications() async -> [InstalledPackage] {
        let fm = FileManager.default
        let appsDir = "/Applications"
        guard let contents = try? fm.contentsOfDirectory(atPath: appsDir) else { return [] }

        return contents.compactMap { item in
            guard item.hasSuffix(".app") else { return nil }
            let path = "\(appsDir)/\(item)"
            let plistPath = "\(path)/Contents/Info.plist"
            let name = item.replacingOccurrences(of: ".app", with: "")

            var version: String?
            var bundleId: String?

            if let plist = NSDictionary(contentsOfFile: plistPath) {
                version = plist["CFBundleShortVersionString"] as? String
                bundleId = plist["CFBundleIdentifier"] as? String
            }

            return InstalledPackage(
                name: name,
                version: version,
                source: .application,
                path: path,
                bundleId: bundleId
            )
        }
    }

    // MARK: - Shell Runner

    private func runCommand(_ path: String, args: [String]) async -> String {
        await withCheckedContinuation { continuation in
            let process = Process()
            let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: path)
            process.arguments = args
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice

            do {
                try process.run()
                process.waitUntilExit()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
            } catch {
                continuation.resume(returning: "")
            }
        }
    }
}
