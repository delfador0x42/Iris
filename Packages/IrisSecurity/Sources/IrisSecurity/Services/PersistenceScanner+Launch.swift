import Foundation

extension PersistenceScanner {
    /// Scan LaunchDaemons directories
    func scanLaunchDaemons() async -> [PersistenceItem] {
        let dirs = [
            "/Library/LaunchDaemons",
            "/System/Library/LaunchDaemons"
        ]
        return await scanLaunchItems(dirs: dirs, type: .launchDaemon)
    }

    /// Scan LaunchAgents directories
    func scanLaunchAgents() async -> [PersistenceItem] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dirs = [
            "/Library/LaunchAgents",
            "/System/Library/LaunchAgents",
            "\(home)/Library/LaunchAgents"
        ]
        return await scanLaunchItems(dirs: dirs, type: .launchAgent)
    }

    private func scanLaunchItems(dirs: [String], type: PersistenceType) async -> [PersistenceItem] {
        var items: [PersistenceItem] = []
        let fm = FileManager.default
        let baseline = BaselineService.shared

        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in contents where file.hasSuffix(".plist") {
                let plistPath = "\(dir)/\(file)"
                guard let plist = NSDictionary(contentsOfFile: plistPath) else { continue }

                let binaryPath = extractBinaryPath(from: plist)
                let autoRun = isAutoRun(plist)
                let (signing, identifier, apple) = verifyBinary(binaryPath)
                let label = file.replacingOccurrences(of: ".plist", with: "")
                let isBaseline = baseline.isBaselineLaunchItem(
                    (plist["Label"] as? String) ?? label
                )

                var ev: [Evidence] = []

                if signing == .unsigned && binaryPath != nil {
                    ev.append(Evidence(factor: "Unsigned binary", weight: 0.5, category: .signing))
                }
                if signing == .adHoc && binaryPath != nil {
                    ev.append(Evidence(factor: "Ad-hoc signed binary", weight: 0.3, category: .signing))
                }
                if signing == .invalid {
                    ev.append(Evidence(factor: "Invalid code signature", weight: 0.6, category: .signing))
                }
                if dir.contains("/Users/") {
                    ev.append(Evidence(factor: "User-level persistence", weight: 0.2, category: .location))
                }
                if !autoRun && !apple {
                    ev.append(Evidence(factor: "Non-standard auto-run configuration", weight: 0.1, category: .context))
                }
                if let bp = binaryPath, !fm.fileExists(atPath: bp) {
                    ev.append(Evidence(factor: "Binary missing from disk", weight: 0.6, category: .context))
                }

                items.append(PersistenceItem(
                    type: type,
                    name: label,
                    path: plistPath,
                    binaryPath: binaryPath,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    isBaselineItem: isBaseline,
                    evidence: ev
                ))
            }
        }
        return items
    }

    /// Extract the executable path from a launchd plist
    private func extractBinaryPath(from plist: NSDictionary) -> String? {
        let lower = Dictionary(uniqueKeysWithValues: plist.map { key, val in
            ((key as? String)?.lowercased() ?? "", val)
        })
        if let program = lower["program"] as? String { return program }
        if let args = lower["programarguments"] as? [String], let first = args.first {
            return first
        }
        return nil
    }

    /// Check if the plist configures automatic execution
    private func isAutoRun(_ plist: NSDictionary) -> Bool {
        let lower = Dictionary(uniqueKeysWithValues: plist.map { key, val in
            ((key as? String)?.lowercased() ?? "", val)
        })
        if lower["runatload"] as? Bool == true { return true }
        if lower["keepalive"] as? Bool == true { return true }
        if lower["startinterval"] != nil { return true }
        if lower["startcalendarinterval"] != nil { return true }
        return false
    }

    nonisolated func verifyBinary(_ path: String?) -> (SigningStatus, String?, Bool) {
        guard let path, FileManager.default.fileExists(atPath: path) else {
            return (.unknown, nil, false)
        }
        return verifier.verify(path)
    }
}
