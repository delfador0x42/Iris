import Foundation

/// File hashing, baseline persistence (save/load)
extension FileSystemBaseline {

    /// Hash all files in a directory — collects paths first, then hashes in parallel
    func hashDirectory(_ dirPath: String) async -> [String: FileEntry] {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: dirPath) else { return [:] }

        // 1. Collect all file paths (fast, sequential)
        var paths: [String] = []
        while let file = enumerator.nextObject() as? String {
            let fullPath = "\(dirPath)/\(file)"
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: fullPath, isDirectory: &isDir),
                  !isDir.boolValue else { continue }
            if let attrs = try? fm.attributesOfItem(atPath: fullPath),
               let size = attrs[.size] as? UInt64, size > 50_000_000 { continue }
            paths.append(fullPath)
        }

        // 2. Hash in parallel (8 concurrent tasks)
        var entries: [String: FileEntry] = [:]
        entries.reserveCapacity(paths.count)

        await withTaskGroup(of: (String, FileEntry?).self) { group in
            var inflight = 0
            for path in paths {
                if inflight >= 8 {
                    if let (p, entry) = await group.next() {
                        if let e = entry { entries[p] = e }
                        inflight -= 1
                    }
                }
                group.addTask { (path, Self.hashFile(path)) }
                inflight += 1
            }
            for await (p, entry) in group {
                if let e = entry { entries[p] = e }
            }
        }

        return entries
    }

    /// Hash a single file — static so it can run off-actor in TaskGroup
    static func hashFile(_ path: String) -> FileEntry? {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: path) else { return nil }
        guard let hash = RustBatchOps.sha256(path: path), !hash.isEmpty else { return nil }

        return FileEntry(
            hash: hash,
            size: attrs[.size] as? UInt64 ?? 0,
            permissions: attrs[.posixPermissions] as? UInt16 ?? 0,
            modificationDate: attrs[.modificationDate] as? Date ?? .distantPast,
            isExecutable: fm.isExecutableFile(atPath: path)
        )
    }

    func saveBaseline() {
        guard let baseline = currentBaseline else { return }
        if let data = try? JSONEncoder().encode(baseline) {
            try? data.write(to: URL(fileURLWithPath: baselinePath), options: .atomic)
        }
    }

    func loadBaseline() -> Baseline? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: baselinePath)) else {
            return nil
        }
        return try? JSONDecoder().decode(Baseline.self, from: data)
    }
}
