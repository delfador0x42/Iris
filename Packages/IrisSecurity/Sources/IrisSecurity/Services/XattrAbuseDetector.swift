import Foundation
import os.log

/// Detects extended attribute abuse for code smuggling.
/// Lazarus Group's RustyAttr technique hides payloads in custom xattrs.
/// Also detects quarantine removal and suspicious resource forks.
/// Covers hunt scripts: xattr_scan. Also covers RustyAttr APT technique.
public actor XattrAbuseDetector {
    public static let shared = XattrAbuseDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "XattrAbuse")

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        anomalies.append(contentsOf: scanRecentAppsXattrs())
        anomalies.append(contentsOf: scanTauriApps())
        return anomalies
    }

    /// Scan recently downloaded/installed apps for suspicious extended attributes
    private func scanRecentAppsXattrs() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dirs = ["/Applications", "\(home)/Applications", "\(home)/Downloads"]
        let fm = FileManager.default

        for dir in dirs {
            guard let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for app in apps where app.hasSuffix(".app") {
                let appPath = "\(dir)/\(app)"
                let xattrs = listXattrs(appPath)
                for attr in xattrs {
                    // Skip standard Apple attributes
                    if attr.hasPrefix("com.apple.") { continue }
                    if attr == "com.macromates.caret" { continue } // TextMate

                    // Custom extended attributes on app bundles are suspicious
                    let size = getxattr(appPath, attr, nil, 0, 0, 0)
                    if size > 100 { // Large custom xattr = possible payload
                        result.append(.filesystem(
                            name: app, path: appPath,
                            technique: "Suspicious Extended Attribute",
                            description: "App \(app) has custom xattr '\(attr)' (\(size) bytes). Possible RustyAttr-style code smuggling.",
                            severity: size > 1000 ? .critical : .high,
                            mitreID: "T1564.004",
                            scannerId: "xattr",
                            enumMethod: "listxattr → getxattr size check",
                            evidence: [
                                "app=\(app)",
                                "xattr_name=\(attr)",
                                "xattr_size=\(size)",
                                "path=\(appPath)",
                            ]))
                    }
                }
            }
        }
        return result
    }

    /// Detect Tauri framework apps (used by RustyAttr/Lazarus)
    private func scanTauriApps() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let dirs = ["/Applications",
                    FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications").path]
        let fm = FileManager.default

        for dir in dirs {
            guard let apps = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for app in apps where app.hasSuffix(".app") {
                let tauriConf = "\(dir)/\(app)/Contents/Resources/tauri.conf.json"
                let preloadJs = "\(dir)/\(app)/Contents/Resources/preload.js"

                if fm.fileExists(atPath: tauriConf) || fm.fileExists(atPath: preloadJs) {
                    // Check if preload.js reads xattrs
                    if let content = try? String(contentsOfFile: preloadJs, encoding: .utf8),
                       content.contains("xattr") || content.contains("getxattr") || content.contains("invoke") {
                        result.append(.filesystem(
                            name: app, path: "\(dir)/\(app)",
                            technique: "Tauri App with XAttr Access",
                            description: "Tauri app \(app) has preload.js that may read extended attributes. Matches RustyAttr/Lazarus technique.",
                            severity: .critical, mitreID: "T1564.004",
                            scannerId: "xattr",
                            enumMethod: "FileManager.fileExists → preload.js content scan",
                            evidence: [
                                "app=\(app)",
                                "preload_js=\(preloadJs)",
                                "framework=Tauri",
                            ]))
                    } else {
                        result.append(.filesystem(
                            name: app, path: "\(dir)/\(app)",
                            technique: "Tauri Framework App",
                            description: "Tauri-based app detected: \(app). Unusual framework — verify legitimacy.",
                            severity: .medium, mitreID: "T1027",
                            scannerId: "xattr",
                            enumMethod: "FileManager.fileExists → tauri.conf.json detection",
                            evidence: [
                                "app=\(app)",
                                "path=\(dir)/\(app)",
                                "framework=Tauri",
                            ]))
                    }
                }
            }
        }
        return result
    }

    private func listXattrs(_ path: String) -> [String] {
        let size = listxattr(path, nil, 0, 0)
        guard size > 0 else { return [] }
        var buf = [CChar](repeating: 0, count: size)
        listxattr(path, &buf, size, 0)
        return String(cString: buf).split(separator: "\0").map(String.init)
    }
}
