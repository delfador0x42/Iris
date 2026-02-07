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

        for dir in dirs {
            guard let contents = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in contents where file.hasSuffix(".plist") {
                let plistPath = "\(dir)/\(file)"
                guard let plist = NSDictionary(contentsOfFile: plistPath) else { continue }

                let binaryPath = extractBinaryPath(from: plist)
                let autoRun = isAutoRun(plist)
                let (signing, identifier, apple) = await verifyBinary(binaryPath)

                var reasons: [String] = []
                if !apple && binaryPath != nil {
                    if signing == .unsigned { reasons.append("Unsigned binary") }
                    if signing == .adHoc { reasons.append("Ad-hoc signed") }
                    if dir.contains("/Users/") { reasons.append("User-level persistence") }
                    if !autoRun { reasons.append("Non-standard auto-run config") }
                }
                if let bp = binaryPath, !fm.fileExists(atPath: bp) {
                    reasons.append("Binary missing from disk")
                }

                items.append(PersistenceItem(
                    type: type,
                    name: file.replacingOccurrences(of: ".plist", with: ""),
                    path: plistPath,
                    binaryPath: binaryPath,
                    signingStatus: signing,
                    signingIdentifier: identifier,
                    isAppleSigned: apple,
                    isSuspicious: !reasons.isEmpty,
                    suspicionReasons: reasons
                ))
            }
        }
        return items
    }

    /// Extract the executable path from a launchd plist
    private func extractBinaryPath(from plist: NSDictionary) -> String? {
        // Lowercase all keys for case-insensitive matching
        let lower = Dictionary(uniqueKeysWithValues: plist.map { key, val in
            ((key as? String)?.lowercased() ?? "", val)
        })

        if let program = lower["program"] as? String {
            return program
        }
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

    func verifyBinary(_ path: String?) async -> (SigningStatus, String?, Bool) {
        guard let path, FileManager.default.fileExists(atPath: path) else {
            return (.unknown, nil, false)
        }
        return await verifier.verify(path)
    }
}
