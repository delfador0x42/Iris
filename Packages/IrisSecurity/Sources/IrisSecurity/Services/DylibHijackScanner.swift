import Foundation
import os.log

/// Scans binaries for dylib hijacking vulnerabilities and active hijacks
public actor DylibHijackScanner {
    public static let shared = DylibHijackScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "DylibHijackScanner")
    private let verifier = SigningVerifier.shared

    /// Scan all running processes for dylib hijack vulnerabilities
    public func scanRunningProcesses(snapshot: ProcessSnapshot? = nil) async -> [DylibHijack] {
        let snap = snapshot ?? ProcessSnapshot.capture()
        var results: [DylibHijack] = []

        for pid in snap.pids {
            let path = snap.path(for: pid)
            guard !path.isEmpty else { continue }
            guard let info = RustMachOParser.parse(path) else { continue }
            // Only scan executables
            guard info.fileType == MH_EXECUTE else { continue }

            let hijacks = analyzeLoadInfo(info)
            results.append(contentsOf: hijacks)
        }

        return results
    }

    /// Scan a specific directory of binaries
    public func scanDirectory(_ dir: String) async -> [DylibHijack] {
        var results: [DylibHijack] = []
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: dir) else { return results }

        while let file = enumerator.nextObject() as? String {
            let path = "\(dir)/\(file)"
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else {
                continue
            }
            guard fm.isExecutableFile(atPath: path) else { continue }
            guard let info = RustMachOParser.parse(path) else { continue }
            guard info.fileType == MH_EXECUTE else { continue }

            let hijacks = analyzeLoadInfo(info)
            results.append(contentsOf: hijacks)
        }

        return results
    }

    private func analyzeLoadInfo(_ info: MachOParser.LoadInfo) -> [DylibHijack] {
        var hijacks: [DylibHijack] = []
        let fm = FileManager.default
        let binaryDir = URL(fileURLWithPath: info.path).deletingLastPathComponent().path

        // 1. Check @rpath dylibs for hijacking
        for dylib in info.loadDylibs where dylib.hasPrefix("@rpath/") {
            let relativeName = String(dylib.dropFirst("@rpath/".count))
            var resolvedPaths: [String] = []

            for rpath in info.rpaths {
                let resolved = resolveRuntimePath(rpath, binaryDir: binaryDir)
                let fullPath = "\(resolved)/\(relativeName)"

                if fm.fileExists(atPath: fullPath) {
                    resolvedPaths.append(fullPath)
                }
            }

            if resolvedPaths.count >= 2 {
                // Multiple copies — potential active hijack
                hijacks.append(DylibHijack(
                    type: .rpathHijack,
                    binaryPath: info.path,
                    dylibPath: resolvedPaths[0],
                    isActiveHijack: true,
                    details: "Multiple copies of \(relativeName) found in @rpath search dirs: \(resolvedPaths.joined(separator: ", "))"
                ))
            } else if resolvedPaths.isEmpty {
                // Missing from all rpaths — vulnerable to planting
                let firstRpath = info.rpaths.first.map { resolveRuntimePath($0, binaryDir: binaryDir) } ?? ""
                let targetPath = "\(firstRpath)/\(relativeName)"
                hijacks.append(DylibHijack(
                    type: .rpathVulnerable,
                    binaryPath: info.path,
                    dylibPath: targetPath,
                    isActiveHijack: false,
                    details: "\(relativeName) not found in any @rpath directory. Attacker could plant a malicious dylib."
                ))
            }
        }

        // 2. Check weak dylibs
        for dylib in info.weakDylibs {
            let resolvedPath: String
            if dylib.hasPrefix("@rpath/") {
                guard let firstRpath = info.rpaths.first else { continue }
                let resolved = resolveRuntimePath(firstRpath, binaryDir: binaryDir)
                resolvedPath = "\(resolved)/\(dylib.dropFirst("@rpath/".count))"
            } else if dylib.hasPrefix("@executable_path/") || dylib.hasPrefix("@loader_path/") {
                resolvedPath = resolveRuntimePath(dylib, binaryDir: binaryDir)
            } else {
                resolvedPath = dylib
            }

            if !fm.fileExists(atPath: resolvedPath) {
                hijacks.append(DylibHijack(
                    type: .weakVulnerable,
                    binaryPath: info.path,
                    dylibPath: resolvedPath,
                    isActiveHijack: false,
                    details: "Weak dylib \(dylib) does not exist. Attacker could plant a malicious dylib."
                ))
            }
        }

        // 3. Check for re-export proxies
        for dylib in info.reexportDylibs {
            hijacks.append(DylibHijack(
                type: .dylibProxy,
                binaryPath: info.path,
                dylibPath: dylib,
                isActiveHijack: false,
                details: "Binary re-exports \(dylib) — could be a proxy dylib."
            ))
        }

        return hijacks
    }

    private func resolveRuntimePath(_ path: String, binaryDir: String) -> String {
        if path.hasPrefix("@executable_path/") {
            return "\(binaryDir)/\(path.dropFirst("@executable_path/".count))"
        }
        if path.hasPrefix("@loader_path/") {
            return "\(binaryDir)/\(path.dropFirst("@loader_path/".count))"
        }
        return path
    }

}
