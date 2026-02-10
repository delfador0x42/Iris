import Foundation

extension PersistenceScanner {
    /// Scan login items from backgroundtaskmanagementagent BTM file
    func scanLoginItems() async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        // Modern BTM file (macOS 13+)
        let btmPaths = [
            "\(home)/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
            "/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm"
        ]

        for btmPath in btmPaths {
            guard let plist = NSDictionary(contentsOfFile: btmPath),
                  let objects = plist["$objects"] as? [Any] else { continue }

            for obj in objects {
                var bookmarkData: Data?
                if let data = obj as? Data {
                    bookmarkData = data
                } else if let dict = obj as? NSDictionary,
                          let data = dict["NS.data"] as? Data {
                    bookmarkData = data
                }
                guard let bookmark = bookmarkData else { continue }
                guard let resolvedPath = resolveBookmark(bookmark) else { continue }
                let name = URL(fileURLWithPath: resolvedPath).lastPathComponent

                let (signing, identifier, apple) = await verifyBinary(resolvedPath)

                var ev: [Evidence] = []
                if !apple {
                    if signing == .unsigned {
                        ev.append(Evidence(factor: "Unsigned login item", weight: 0.5, category: .signing))
                    }
                    if signing == .adHoc {
                        ev.append(Evidence(factor: "Ad-hoc signed login item", weight: 0.3, category: .signing))
                    }
                }

                items.append(PersistenceItem(
                    type: .loginItem,
                    name: name,
                    path: btmPath,
                    binaryPath: resolvedPath,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    evidence: ev
                ))
            }
        }

        // Also scan /Applications/*/Contents/Library/LoginItems/
        let fm = FileManager.default
        let appsDir = "/Applications"
        if let apps = try? fm.contentsOfDirectory(atPath: appsDir) {
            for app in apps where app.hasSuffix(".app") {
                let loginItemsDir = "\(appsDir)/\(app)/Contents/Library/LoginItems"
                guard let loginItems = try? fm.contentsOfDirectory(atPath: loginItemsDir) else {
                    continue
                }
                for item in loginItems where item.hasSuffix(".app") {
                    let itemPath = "\(loginItemsDir)/\(item)"
                    let name = item.replacingOccurrences(of: ".app", with: "")
                    let (signing, identifier, apple) = await verifyBinary(itemPath)

                    items.append(PersistenceItem(
                        type: .loginItem,
                        name: "\(name) (via \(app))",
                        path: itemPath,
                        binaryPath: itemPath,
                        signingStatus: signing,
                        signingIdentifier: identifier,
                        isAppleSigned: apple
                    ))
                }
            }
        }

        return items
    }

    private func resolveBookmark(_ data: Data) -> String? {
        var isStale = false
        guard let url = try? URL(
            resolvingBookmarkData: data,
            options: [.withoutUI, .withoutMounting],
            relativeTo: nil,
            bookmarkDataIsStale: &isStale
        ) else {
            return extractPathFromBookmarkData(data)
        }
        return url.path
    }

    private func extractPathFromBookmarkData(_ data: Data) -> String? {
        guard let str = String(data: data, encoding: .utf8) else { return nil }
        let patterns = ["/Applications/", "/Users/", "/Library/", "/usr/"]
        for pattern in patterns {
            if let range = str.range(of: pattern) {
                let remaining = str[range.lowerBound...]
                var path = ""
                for char in remaining {
                    if char.asciiValue == nil || char.asciiValue! < 32 { break }
                    path.append(char)
                }
                if !path.isEmpty { return path }
            }
        }
        return nil
    }
}
