import Foundation
import os.log

/// Detects data staging for exfiltration in /tmp, /var/tmp, ~/.local-*, /Users/Shared.
/// Malware stages stolen data before exfil: zip/tar archives, credential copies, screenshots.
/// Covers hunt scripts: staging_exfil. Also covers RustyAttr, Cuckoo, FlexibleFerret patterns.
public actor StagingDetector {
    public static let shared = StagingDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "StagingDetector")

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path

        anomalies.append(contentsOf: scanTmpArchives())
        anomalies.append(contentsOf: scanHiddenStagingDirs(home: home))
        anomalies.append(contentsOf: scanCuckooPatterns())
        anomalies.append(contentsOf: scanSharedStaging())
        return anomalies
    }

    /// Archives in /tmp or /var/tmp — classic staging before exfil
    private func scanTmpArchives() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let dirs = ["/tmp", "/var/tmp", NSTemporaryDirectory()]
        let fm = FileManager.default
        let archiveExts = Set(["zip", "tar", "gz", "tgz", "7z", "rar", "bz2"])

        for dir in dirs {
            guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
            for file in files {
                let ext = (file as NSString).pathExtension.lowercased()
                guard archiveExts.contains(ext) else { continue }
                let path = "\(dir)/\(file)"
                guard let attrs = try? fm.attributesOfItem(atPath: path),
                      let size = attrs[.size] as? UInt64, size > 1024 else { continue }
                result.append(.filesystem(
                    name: file, path: path,
                    technique: "Staged Archive",
                    description: "Archive in temp directory: \(file) (\(size / 1024)KB). Possible exfiltration staging.",
                    severity: size > 10_000_000 ? .high : .medium, mitreID: "T1074.001",
                    scannerId: "staging",
                    enumMethod: "FileManager.contentsOfDirectory → temp dir archive scan",
                    evidence: [
                        "file=\(file)",
                        "path=\(path)",
                        "size_bytes=\(size)",
                        "extension=\(ext)",
                    ]))
            }
        }
        return result
    }

    /// Hidden staging directories: ~/.local-<UUID>/, ~/.gp, ~/.cache_* (Cuckoo, FlexibleFerret)
    private func scanHiddenStagingDirs(home: String) -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        guard let contents = try? FileManager.default.contentsOfDirectory(atPath: home) else { return result }

        for item in contents {
            let path = "\(home)/\(item)"
            var isDir: ObjCBool = false
            guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue else { continue }

            // Suspicious hidden directories
            if item.hasPrefix(".local-") || item == ".gp" ||
               (item.hasPrefix(".cache_") && item != ".cache") {
                result.append(.filesystem(
                    name: item, path: path,
                    technique: "Hidden Staging Directory",
                    description: "Suspicious hidden directory: ~/\(item). Matches malware staging pattern (Cuckoo/FlexibleFerret).",
                    severity: .high, mitreID: "T1074.001",
                    scannerId: "staging",
                    enumMethod: "FileManager.contentsOfDirectory → home hidden dir scan",
                    evidence: [
                        "directory=\(item)",
                        "path=\(path)",
                        "pattern=hidden staging",
                    ]))
            }
        }
        return result
    }

    /// Cuckoo stealer patterns: screenshots in /tmp/.cache_*.png, pw.dat files
    private func scanCuckooPatterns() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let fm = FileManager.default
        guard let tmpFiles = try? fm.contentsOfDirectory(atPath: "/tmp") else { return result }

        for file in tmpFiles {
            if file.hasPrefix(".cache_") && file.hasSuffix(".png") {
                result.append(.filesystem(
                    name: file, path: "/tmp/\(file)",
                    technique: "Staged Screenshot",
                    description: "Hidden screenshot in /tmp: \(file). Matches Cuckoo stealer pattern.",
                    severity: .critical, mitreID: "T1113",
                    scannerId: "staging",
                    enumMethod: "FileManager.contentsOfDirectory → /tmp hidden png scan",
                    evidence: [
                        "file=\(file)",
                        "path=/tmp/\(file)",
                        "pattern=Cuckoo stealer",
                    ]))
            }
        }

        // Check for pw.dat in hidden dirs under home
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        if let contents = try? fm.contentsOfDirectory(atPath: home) {
            for dir in contents where dir.hasPrefix(".local-") {
                let pwPath = "\(home)/\(dir)/pw.dat"
                if fm.fileExists(atPath: pwPath) {
                    result.append(.filesystem(
                        name: "pw.dat", path: pwPath,
                        technique: "Stolen Password File",
                        description: "Cleartext password file found: \(pwPath). Matches Cuckoo stealer pattern.",
                        severity: .critical, mitreID: "T1555",
                        scannerId: "staging",
                        enumMethod: "FileManager.fileExists → ~/.local-*/pw.dat check",
                        evidence: [
                            "file=pw.dat",
                            "path=\(pwPath)",
                            "parent_dir=\(dir)",
                        ]))
                }
            }
        }
        return result
    }

    /// /Users/Shared is commonly used by malware for staging (Banshee, CookieMiner)
    private func scanSharedStaging() -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let shared = "/Users/Shared"
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: shared) else { return result }

        let suspicious = files.filter { name in
            let ext = (name as NSString).pathExtension.lowercased()
            return ext == "sh" || ext == "py" || ext == "rb" || name == "xmrig2" ||
                   name == "xmrig" || name.hasSuffix(".dylib")
        }

        for file in suspicious {
            result.append(.filesystem(
                name: file, path: "\(shared)/\(file)",
                technique: "Suspicious File in /Users/Shared",
                description: "Executable/script in /Users/Shared: \(file). Common malware staging location.",
                severity: .high, mitreID: "T1074.001",
                scannerId: "staging",
                enumMethod: "FileManager.contentsOfDirectory → /Users/Shared scan",
                evidence: [
                    "file=\(file)",
                    "path=\(shared)/\(file)",
                    "location=/Users/Shared",
                ]))
        }
        return result
    }
}
