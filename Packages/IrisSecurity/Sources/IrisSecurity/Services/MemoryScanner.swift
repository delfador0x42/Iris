import Foundation
import os.log
import CryptoKit

/// Scans process memory via native Mach APIs (no shell-outs).
/// Three detection layers:
/// 1. RWX regions via mach_vm_region (shellcode, JIT abuse)
/// 2. Mach-O headers in ANONYMOUS regions (reflective loading)
/// 3. Thread count anomalies (injected threads)
///
/// ZERO-TRUST: No process name allowlists. Detection is technique-based:
/// - RWX: any process with writable+executable memory (potential shellcode)
/// - Reflective: Mach-O headers in anonymous (non-file-backed) memory
///   File-backed executable regions (normal __TEXT) are NOT flagged.
public actor MemoryScanner {
    public static let shared = MemoryScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "MemoryScanner")

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        for pid in snapshot.pids {
            guard pid > 0 else { continue }
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/") { continue }
            anomalies.append(contentsOf: scanMemoryRegions(pid: pid, name: name, path: path))
            anomalies.append(contentsOf: checkThreadCount(pid: pid, name: name, path: path))
        }
        return anomalies
    }

    /// Walk VM regions via mach_vm_region — detect RWX + Mach-O in anonymous memory.
    /// Uses VM_REGION_EXTENDED_INFO to distinguish file-backed vs anonymous regions.
    /// File-backed executable regions (normal loaded binaries) always have Mach-O magic
    /// at the __TEXT start — that's NOT reflective loading, that's normal binary loading.
    /// Only anonymous executable regions with Mach-O magic = actual reflective injection.
    private func scanMemoryRegions(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return [] }
        defer { mach_port_deallocate(mach_task_self_, task) }

        var address: mach_vm_address_t = 0
        var rwxCount = 0
        var machoInAnon = false
        var machoAnonAddr: mach_vm_address_t = 0
        var machoAnonSize: mach_vm_size_t = 0
        var anomalies: [ProcessAnomaly] = []

        while true {
            var size: mach_vm_size_t = 0
            var info = vm_region_extended_info_data_t()
            var infoCount = mach_msg_type_number_t(
                MemoryLayout<vm_region_extended_info_data_t>.size / MemoryLayout<Int32>.size)
            var objectName: mach_port_t = 0
            let kr = withUnsafeMutablePointer(to: &info) { ptr in
                ptr.withMemoryRebound(to: Int32.self, capacity: Int(infoCount)) {
                    mach_vm_region(task, &address, &size,
                                  VM_REGION_EXTENDED_INFO, $0, &infoCount, &objectName)
                }
            }
            guard kr == KERN_SUCCESS else { break }

            let isExec = info.protection & VM_PROT_EXECUTE != 0
            let isWrite = info.protection & VM_PROT_WRITE != 0

            // Anonymous = SM_PRIVATE or SM_EMPTY (not SM_COW which is file-backed)
            let isAnonymous = info.share_mode == UInt8(SM_PRIVATE)
                || info.share_mode == UInt8(SM_EMPTY)

            // RWX: current protection has both write and execute
            if isExec && isWrite { rwxCount += 1 }

            // Check for Mach-O magic ONLY in anonymous executable regions.
            // File-backed regions always have Mach-O magic (that's __TEXT of loaded binaries).
            if isExec && isAnonymous && !machoInAnon {
                if checkMachOMagic(task: task, addr: address, size: size) {
                    machoInAnon = true
                    machoAnonAddr = address
                    machoAnonSize = size
                }
            }

            address += size
            if address == 0 { break }
        }

        if rwxCount > 0 {
            // Contradiction-based RWX detection.
            // Source 1: mach_vm_region says process has RWX memory.
            // Source 2: Process entitlements declare JIT capability.
            // If entitlements declare JIT (allow-jit or allow-unsigned-executable-memory),
            // RWX is expected — no contradiction. If NO JIT entitlement but RWX exists,
            // that's a genuine contradiction worth reporting.
            let signing = CodeSignValidator.validate(path: path)
            let hasJitEntitlement: Bool
            if let ents = signing.entitlements {
                hasJitEntitlement = (ents["com.apple.security.cs.allow-jit"] as? Bool == true)
                    || (ents["com.apple.security.cs.allow-unsigned-executable-memory"] as? Bool == true)
            } else {
                hasJitEntitlement = false
            }

            let severity: AnomalySeverity = hasJitEntitlement ? .low : .high
            let jitNote = hasJitEntitlement ? " (JIT entitlement declared — expected)" : " (no JIT entitlement — suspicious)"

            anomalies.append(.forProcess(
                pid: pid, name: name, path: path,
                technique: "RWX Memory Regions",
                description: "\(name) has \(rwxCount) RWX region(s).\(jitNote)",
                severity: severity, mitreID: "T1055.012",
                scannerId: "memory",
                enumMethod: "mach_vm_region(VM_REGION_EXTENDED_INFO) + entitlement cross-validation",
                evidence: [
                    "pid: \(pid)", "rwx_count: \(rwxCount)", "process: \(name)",
                    "jit_entitlement: \(hasJitEntitlement)",
                    "signing_id: \(signing.signingIdentifier ?? "unknown")",
                ]))
        }

        if machoInAnon {
            anomalies.append(.forProcess(
                pid: pid, name: name, path: path,
                technique: "Reflective Code Loading",
                description: "\(name) has Mach-O headers in anonymous (non-file-backed) executable memory at 0x\(String(machoAnonAddr, radix: 16)). Reflective injection.",
                severity: .critical, mitreID: "T1620",
                scannerId: "memory",
                enumMethod: "mach_vm_region(VM_REGION_EXTENDED_INFO) + mach_vm_read_overwrite magic check",
                evidence: [
                    "pid: \(pid)",
                    "anon_region: 0x\(String(machoAnonAddr, radix: 16))+\(machoAnonSize / 1024)KB",
                    "share_mode: SM_PRIVATE (anonymous)",
                    "process: \(name)",
                ]))
        }
        return anomalies
    }
}
