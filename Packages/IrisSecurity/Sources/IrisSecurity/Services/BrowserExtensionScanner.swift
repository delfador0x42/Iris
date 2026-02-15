import Foundation
import os.log

/// Scans browser extensions for excessive permissions that enable data theft.
/// Covers hunt scripts: browser_extensions.
/// Checks Chrome, Brave, Edge, Firefox extension manifests.
public actor BrowserExtensionScanner {
    public static let shared = BrowserExtensionScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "BrowserExts")

    /// Permissions that enable significant data access
    private let dangerousPermissions = Set([
        "<all_urls>", "*://*/*", "http://*/*", "https://*/*",
        "webRequest", "webRequestBlocking", "cookies", "tabs",
        "history", "bookmarks", "browsingData", "clipboardRead",
        "nativeMessaging", "proxy", "management", "debugger",
    ])

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let appSupport = "\(home)/Library/Application Support"

        // Chrome-based browsers
        let chromium = [
            ("Google/Chrome", "Chrome"),
            ("BraveSoftware/Brave-Browser", "Brave"),
            ("Microsoft Edge", "Edge"),
            ("Vivaldi", "Vivaldi"),
        ]
        for (dir, browser) in chromium {
            let extDir = "\(appSupport)/\(dir)/Default/Extensions"
            anomalies.append(contentsOf: scanChromiumExtensions(dir: extDir, browser: browser))
        }

        // Firefox
        let firefoxDir = "\(appSupport)/Firefox/Profiles"
        anomalies.append(contentsOf: scanFirefoxExtensions(profilesDir: firefoxDir))
        return anomalies
    }

    private func scanChromiumExtensions(dir: String, browser: String) -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let fm = FileManager.default
        guard let extIds = try? fm.contentsOfDirectory(atPath: dir) else { return result }

        for extId in extIds {
            let extPath = "\(dir)/\(extId)"
            guard let versions = try? fm.contentsOfDirectory(atPath: extPath),
                  let latest = versions.sorted().last else { continue }
            let manifestPath = "\(extPath)/\(latest)/manifest.json"
            guard let data = fm.contents(atPath: manifestPath),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { continue }

            let name = json["name"] as? String ?? extId
            let perms = (json["permissions"] as? [Any])?.compactMap { $0 as? String } ?? []
            let hostPerms = (json["host_permissions"] as? [String]) ?? []
            let allPerms = Set(perms + hostPerms)
            let dangerous = allPerms.intersection(dangerousPermissions)

            if dangerous.count >= 3 {
                result.append(.filesystem(
                    name: name, path: manifestPath,
                    technique: "Overprivileged Browser Extension",
                    description: "\(browser) extension '\(name)' has \(dangerous.count) dangerous permissions: \(dangerous.sorted().joined(separator: ", "))",
                    severity: dangerous.contains("nativeMessaging") ? .high : .medium,
                    mitreID: "T1176"))
            }
        }
        return result
    }

    private func scanFirefoxExtensions(profilesDir: String) -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let fm = FileManager.default
        guard let profiles = try? fm.contentsOfDirectory(atPath: profilesDir) else { return result }

        for profile in profiles {
            let addonsPath = "\(profilesDir)/\(profile)/addons.json"
            guard let data = fm.contents(atPath: addonsPath),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let addons = json["addons"] as? [[String: Any]] else { continue }

            for addon in addons {
                let name = addon["name"] as? String ?? "unknown"
                let active = addon["active"] as? Bool ?? false
                let signed = addon["signedState"] as? Int ?? 0
                if active && signed == 0 {
                    result.append(.filesystem(
                        name: name, path: addonsPath,
                        technique: "Unsigned Firefox Extension",
                        description: "Firefox extension '\(name)' is unsigned. May be sideloaded malware.",
                        severity: .high, mitreID: "T1176"))
                }
            }
        }
        return result
    }
}
