import Foundation

extension PersistenceScanner {
    /// Scan browser extensions (Safari, Chrome, Firefox)
    func scanBrowserExtensions() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let safari = await scanSafariExtensions()
        let chrome = await scanChromeExtensions()
        let firefox = await scanFirefoxExtensions()
        items.append(contentsOf: safari)
        items.append(contentsOf: chrome)
        items.append(contentsOf: firefox)
        return items
    }

    private func scanSafariExtensions() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []

        // Use pluginkit to enumerate Safari extensions
        for pluginType in ["com.apple.Safari.extension", "com.apple.Safari.content-blocker"] {
            let output = await runCommand("/usr/bin/pluginkit", args: ["-mAvv", "-p", pluginType])
            var currentPath: String?
            var currentName: String?

            for line in output.split(separator: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("Path = ") {
                    currentPath = String(trimmed.dropFirst("Path = ".count))
                } else if trimmed.hasPrefix("Display Name = ") {
                    currentName = String(trimmed.dropFirst("Display Name = ".count))
                }

                if let path = currentPath, let name = currentName {
                    items.append(PersistenceItem(
                        type: .browserExtension,
                        name: "Safari: \(name)",
                        path: path
                    ))
                    currentPath = nil
                    currentName = nil
                }
            }
        }
        return items
    }

    private func scanChromeExtensions() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let chromeBase = "\(home)/Library/Application Support/Google/Chrome"

        // Check Default and Profile* directories
        var profiles = ["Default"]
        if let dirs = try? FileManager.default.contentsOfDirectory(atPath: chromeBase) {
            for dir in dirs where dir.hasPrefix("Profile ") {
                profiles.append(dir)
            }
        }

        for profile in profiles {
            let prefsPath = "\(chromeBase)/\(profile)/Preferences"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: prefsPath)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let extensions = json["extensions"] as? [String: Any],
                  let settings = extensions["settings"] as? [String: Any] else { continue }

            for (extId, extData) in settings {
                guard let extDict = extData as? [String: Any] else { continue }
                // Skip disabled or default extensions
                if extDict["state"] as? Int == 0 { continue }
                if extDict["was_installed_by_default"] as? Bool == true { continue }

                let manifest = extDict["manifest"] as? [String: Any]
                let name = manifest?["name"] as? String ?? extId
                let extPath = extDict["path"] as? String ??
                    "\(chromeBase)/\(profile)/Extensions/\(extId)"

                items.append(PersistenceItem(
                    type: .browserExtension,
                    name: "Chrome: \(name)",
                    path: extPath
                ))
            }
        }
        return items
    }

    private func scanFirefoxExtensions() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let ffBase = "\(home)/Library/Application Support/Firefox/Profiles"

        guard let profiles = try? FileManager.default.contentsOfDirectory(atPath: ffBase) else {
            return items
        }

        for profile in profiles {
            let addonsPath = "\(ffBase)/\(profile)/addons.json"
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: addonsPath)),
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let addons = json["addons"] as? [[String: Any]] else { continue }

            for addon in addons {
                // Skip disabled
                if addon["active"] as? Bool == false { continue }
                let name = addon["name"] as? String ?? "Unknown"
                let addonId = addon["id"] as? String ?? ""
                let path = "\(ffBase)/\(profile)/extensions/\(addonId)"

                items.append(PersistenceItem(
                    type: .browserExtension,
                    name: "Firefox: \(name)",
                    path: path
                ))
            }
        }
        return items
    }
}
