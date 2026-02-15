import Foundation
import os.log

/// Detects files using masquerading tricks: double extensions, Unicode homoglyphs,
/// null bytes in filenames, and hidden executables in non-standard locations.
/// Covers hunt scripts: hidden_files.
public actor HiddenFileDetector {
    public static let shared = HiddenFileDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "HiddenFiles")

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let dirs = ["\(home)/Downloads", "\(home)/Desktop", "\(home)/Documents", "/tmp"]

        for dir in dirs {
            anomalies.append(contentsOf: scanDirectory(dir))
        }
        return anomalies
    }

    private func scanDirectory(_ dir: String) -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        guard let files = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return result }

        for file in files {
            let path = "\(dir)/\(file)"

            // Double extensions: document.pdf.app, photo.jpg.command
            if hasDoubleExtension(file) {
                result.append(.filesystem(
                    name: file, path: path,
                    technique: "Double Extension Masquerade",
                    description: "File uses double extension to disguise type: \(file)",
                    severity: .high, mitreID: "T1036.007"))
            }

            // Unicode RLO (Right-to-Left Override) character
            if file.contains("\u{202E}") {
                result.append(.filesystem(
                    name: file, path: path,
                    technique: "Unicode RLO Filename",
                    description: "Filename contains Right-to-Left Override character to hide real extension.",
                    severity: .critical, mitreID: "T1036.002"))
            }

            // Null bytes in filename
            if file.contains("\0") {
                result.append(.filesystem(
                    name: file, path: path,
                    technique: "Null Byte in Filename",
                    description: "Filename contains null byte — may exploit path parsing vulnerabilities.",
                    severity: .critical, mitreID: "T1036"))
            }

            // Executable hidden as non-executable extension
            if isExecutableMasqueradingAsDocument(path: path, name: file) {
                result.append(.filesystem(
                    name: file, path: path,
                    technique: "Executable Masquerading as Document",
                    description: "File \(file) is a Mach-O binary disguised as a document.",
                    severity: .critical, mitreID: "T1036.008"))
            }
        }
        return result
    }

    private func hasDoubleExtension(_ name: String) -> Bool {
        let dangerous = Set(["app", "command", "sh", "py", "rb", "pl", "scpt", "terminal", "pkg", "dmg"])
        let parts = name.split(separator: ".")
        guard parts.count >= 3 else { return false }
        let lastExt = String(parts.last!).lowercased()
        return dangerous.contains(lastExt)
    }

    /// Check if a file with a document extension is actually a Mach-O binary
    private func isExecutableMasqueradingAsDocument(path: String, name: String) -> Bool {
        let docExts = Set(["pdf", "doc", "docx", "txt", "jpg", "png", "mp4"])
        let ext = (name as NSString).pathExtension.lowercased()
        guard docExts.contains(ext) else { return false }

        // Read first 4 bytes — check for Mach-O magic
        guard let fh = FileHandle(forReadingAtPath: path) else { return false }
        defer { fh.closeFile() }
        let header = fh.readData(ofLength: 4)
        guard header.count == 4 else { return false }

        let magic = header.withUnsafeBytes { $0.load(as: UInt32.self) }
        let machoMagics: Set<UInt32> = [0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xBEBAFECA]
        return machoMagics.contains(magic)
    }
}
