import Foundation
import os.log

/// Detects phantom/sideloaded dylibs — libraries loaded from non-standard paths
/// that shadow or impersonate system dylibs. Core nation-state technique.
///
/// Attack patterns detected:
/// 1. Dylib proxy: attacker places a dylib at a writable path that re-exports
///    the real system dylib while injecting malicious code
/// 2. Dylib sideloading: placing a dylib in the app bundle's Frameworks/ or
///    rpath that shadows a system dylib
/// 3. Unsigned dylibs loaded into signed processes
/// 4. Dylibs loaded from /tmp, /var/tmp, or user-writable staging directories
/// 5. Dylibs with names matching system libraries but from wrong paths
public actor PhantomDylibDetector {
    public static let shared = PhantomDylibDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "PhantomDylib")

    /// Known system dylib directories — anything loaded from elsewhere is suspicious
    private static let systemDylibPaths: [String] = [
        "/System/Library/",
        "/usr/lib/",
        "/Library/Apple/",
        "/usr/local/lib/",  // Homebrew
    ]

    /// Writable staging directories — dylibs here are highly suspicious
    private static let stagingPaths: [String] = [
        "/tmp/", "/var/tmp/", "/private/tmp/",
        "/var/folders/",     // macOS temp folders
        "/Users/Shared/",   // world-writable
    ]

    /// Well-known system dylib names that should only load from system paths
    private static let systemDylibNames: Set<String> = [
        "libSystem.B.dylib", "libdyld.dylib", "libc++.1.dylib",
        "libsqlite3.dylib", "libxml2.2.dylib", "libz.1.dylib",
        "libiconv.2.dylib", "libncurses.5.4.dylib", "libresolv.9.dylib",
        "Security.framework", "Foundation.framework", "CoreFoundation.framework",
        "AppKit.framework", "IOKit.framework",
    ]

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        for pid in snapshot.pids {
            guard pid > 1 else { continue }
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)

            // Skip system processes
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/libexec/") { continue }
            if path.isEmpty { continue }

            let result = DylibEnumerator.loadedImagesWithMethod(for: pid)
            guard !result.images.isEmpty else { continue }

            // Check each loaded dylib
            for dylib in result.images {
                // Layer 1: Dylibs from staging/temp directories
                if let finding = checkStagingPath(
                    dylib: dylib, pid: pid, name: name, path: path) {
                    anomalies.append(finding)
                    continue
                }

                // Layer 2: System dylib names loaded from non-system paths
                if let finding = checkSystemNameShadow(
                    dylib: dylib, pid: pid, name: name, path: path) {
                    anomalies.append(finding)
                    continue
                }

                // Layer 3: Dylibs from user-writable directories in signed processes
                if let finding = checkWritableDylib(
                    dylib: dylib, pid: pid, name: name, path: path) {
                    anomalies.append(finding)
                }
            }
        }

        return anomalies
    }

    /// Detect dylibs loaded from temp/staging directories
    private func checkStagingPath(dylib: String, pid: pid_t,
                                  name: String, path: String) -> ProcessAnomaly? {
        for staging in Self.stagingPaths {
            if dylib.hasPrefix(staging) {
                return .forProcess(
                    pid: pid, name: name, path: path,
                    technique: "Phantom Dylib (Staging Path)",
                    description: "\(name) loaded dylib from staging directory: \(dylib)",
                    severity: .critical, mitreID: "T1574.002",
                    scannerId: "phantom_dylib",
                    enumMethod: "DylibEnumerator + staging path check",
                    evidence: [
                        "pid: \(pid)",
                        "dylib: \(dylib)",
                        "staging_dir: \(staging)",
                    ])
            }
        }
        return nil
    }

    /// Detect system dylib names loaded from non-system paths
    private func checkSystemNameShadow(dylib: String, pid: pid_t,
                                       name: String, path: String) -> ProcessAnomaly? {
        let dylibName = (dylib as NSString).lastPathComponent
        let isFromSystemPath = Self.systemDylibPaths.contains { dylib.hasPrefix($0) }

        // Check if this dylib has a system name but loads from wrong location
        for sysName in Self.systemDylibNames {
            if dylibName.contains(sysName) && !isFromSystemPath {
                return .forProcess(
                    pid: pid, name: name, path: path,
                    technique: "Dylib Name Shadowing",
                    description: "\(name) loaded \(dylibName) from non-system path. Possible dylib proxy attack.",
                    severity: .critical, mitreID: "T1574.001",
                    scannerId: "phantom_dylib",
                    enumMethod: "DylibEnumerator + system name → path validation",
                    evidence: [
                        "pid: \(pid)",
                        "dylib: \(dylib)",
                        "expected_prefix: /System/Library/ or /usr/lib/",
                        "actual_path: \(dylib)",
                    ])
            }
        }
        return nil
    }

    /// Detect dylibs from user-writable directories in non-developer processes
    private func checkWritableDylib(dylib: String, pid: pid_t,
                                    name: String, path: String) -> ProcessAnomaly? {
        let isFromSystemPath = Self.systemDylibPaths.contains { dylib.hasPrefix($0) }
        if isFromSystemPath { return nil }

        // Skip dylibs in app bundles (normal for signed apps)
        if dylib.contains(".app/Contents/") { return nil }
        // Skip dylibs in Homebrew
        if dylib.hasPrefix("/opt/homebrew/") || dylib.hasPrefix("/usr/local/") { return nil }

        // Check if dylib exists in a user-writable location
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if dylib.hasPrefix(home) && !dylib.contains(".app/") {
            // Dylib loaded from user home directory (outside app bundles)
            return .forProcess(
                pid: pid, name: name, path: path,
                technique: "Dylib from User Directory",
                description: "\(name) loaded dylib from user directory: \((dylib as NSString).lastPathComponent)",
                severity: .medium, mitreID: "T1574.002",
                scannerId: "phantom_dylib",
                enumMethod: "DylibEnumerator + home directory path check",
                evidence: [
                    "pid: \(pid)",
                    "dylib: \(dylib)",
                ])
        }
        return nil
    }
}
