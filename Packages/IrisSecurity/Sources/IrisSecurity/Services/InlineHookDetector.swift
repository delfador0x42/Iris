import Foundation
import os.log
import MachO

/// Detects inline function hooks (trampolines/detours) in loaded system libraries.
/// Nation-state actors hook security-critical functions to intercept EDR calls,
/// bypass code signing checks, or hide from process enumeration.
///
/// Detection: For each non-system process, enumerate loaded dylibs via TASK_DYLD_INFO.
/// For security-critical libraries, read the first instructions at the library's
/// __TEXT base and check for ARM64 trampoline patterns (LDR X16/X17 + BR).
public actor InlineHookDetector {
    public static let shared = InlineHookDetector()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "InlineHook")

    /// ARM64 trampoline signatures (first 8 bytes of a hooked function)
    /// LDR X16, #8 = 0x58000050; BR X16 = 0xd61f0200
    /// LDR X17, #8 = 0x58000071; BR X17 = 0xd61f0220
    private let trampolinePatterns: [(UInt32, UInt32)] = [
        (0x58000050, 0xd61f0200), // LDR X16, #8; BR X16
        (0x58000071, 0xd61f0220), // LDR X17, #8; BR X17
    ]

    /// System libraries that are high-value hook targets for attackers
    private let criticalLibs: Set<String> = [
        "libsystem_kernel.dylib",    // syscall wrappers (ptrace, sysctl, proc_info)
        "libsystem_c.dylib",         // open, execve, dlopen
        "libdyld.dylib",             // dlsym, _dyld_image_count
        "Security",                  // SecCodeCheckValidity, SecStaticCodeCreateWithPath
        "libsystem_info.dylib",      // getpwnam, getgrnam
        "libsystem_malloc.dylib",    // malloc interposition detection
        "libsystem_pthread.dylib",   // thread creation hooks
    ]

    /// Processes that legitimately hook (development tools, debuggers)
    private let allowedHookers = Set([
        "Xcode", "lldb", "dtrace", "Instruments", "lldb-rpc-server",
        "frida-server", "frida-agent", // Explicit pentesting tools
    ])

    public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        for pid in snapshot.pids {
            guard pid > 1 else { continue }
            let name = snapshot.name(for: pid)
            let path = snapshot.path(for: pid)
            // Skip system processes and known hookers
            if allowedHookers.contains(name) { continue }
            if path.hasPrefix("/System/") || path.hasPrefix("/usr/") { continue }

            anomalies.append(contentsOf: checkLoadedLibraries(pid: pid, name: name, path: path))
        }
        return anomalies
    }

    /// Enumerate loaded dylibs and check critical ones for hooks.
    private func checkLoadedLibraries(pid: pid_t, name: String, path: String) -> [ProcessAnomaly] {
        var task: mach_port_t = 0
        guard task_for_pid(mach_task_self_, pid, &task) == KERN_SUCCESS else { return [] }
        defer { mach_port_deallocate(mach_task_self_, task) }

        // Get dyld_all_image_infos via TASK_DYLD_INFO
        var dyldInfo = task_dyld_info_data_t()
        var count = mach_msg_type_number_t(
            MemoryLayout<task_dyld_info_data_t>.size / MemoryLayout<natural_t>.size)
        let kr = withUnsafeMutablePointer(to: &dyldInfo) { ptr in
            ptr.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(task, task_flavor_t(TASK_DYLD_INFO), $0, &count)
            }
        }
        guard kr == KERN_SUCCESS, dyldInfo.all_image_info_addr != 0 else { return [] }

        // Read dyld_all_image_infos
        var allInfo = dyld_all_image_infos()
        guard readMem(task, dyldInfo.all_image_info_addr,
                      &allInfo, MemoryLayout<dyld_all_image_infos>.size) else { return [] }
        let imageCount = min(Int(allInfo.infoArrayCount), 2000)
        guard imageCount > 0 else { return [] }

        // Read image info array
        let arrayAddr = unsafeBitCast(allInfo.infoArray, to: UInt.self)
        guard arrayAddr != 0 else { return [] }
        let stride = MemoryLayout<dyld_image_info>.stride
        let arraySize = imageCount * stride
        let buf = UnsafeMutableRawPointer.allocate(byteCount: arraySize, alignment: 8)
        defer { buf.deallocate() }
        var outSize: mach_vm_size_t = 0
        let readKr = mach_vm_read_overwrite(
            task, mach_vm_address_t(arrayAddr), mach_vm_size_t(arraySize),
            mach_vm_address_t(UInt(bitPattern: buf)), &outSize)
        guard readKr == KERN_SUCCESS else { return [] }

        var anomalies: [ProcessAnomaly] = []

        // Check each loaded image
        for i in 0..<imageCount {
            let imageInfo = buf.advanced(by: i * stride).load(as: dyld_image_info.self)
            let loadAddr = unsafeBitCast(imageInfo.imageLoadAddress, to: UInt64.self)
            guard loadAddr != 0 else { continue }

            // Read image name from target process
            let nameAddr = unsafeBitCast(imageInfo.imageFilePath, to: UInt.self)
            guard nameAddr != 0 else { continue }
            let nameReadBuf = UnsafeMutableRawPointer.allocate(byteCount: 256, alignment: 1)
            defer { nameReadBuf.deallocate() }
            nameReadBuf.initializeMemory(as: UInt8.self, repeating: 0, count: 256)
            var nameOutSize: mach_vm_size_t = 0
            let nameKr = mach_vm_read_overwrite(
                task, mach_vm_address_t(nameAddr), 255,
                mach_vm_address_t(UInt(bitPattern: nameReadBuf)), &nameOutSize)
            guard nameKr == KERN_SUCCESS else { continue }
            let imageName = String(cString: nameReadBuf.assumingMemoryBound(to: CChar.self))
            let libName = (imageName as NSString).lastPathComponent

            // Only check critical libraries
            guard criticalLibs.contains(libName) else { continue }

            // Read first 16 bytes at load address (first function entry)
            if let hooked = checkForTrampoline(task: task, addr: loadAddr, libName: libName) {
                anomalies.append(.forProcess(
                    pid: pid, name: name, path: path,
                    technique: "Inline Function Hook",
                    description: "\(name) has hooked \(libName). Trampoline detected at library load address.",
                    severity: .critical, mitreID: "T1574.013",
                    scannerId: "inline_hook",
                    enumMethod: "TASK_DYLD_INFO + mach_vm_read (trampoline pattern scan)",
                    evidence: [
                        "pid: \(pid)", "hooked_lib: \(libName)",
                        "pattern: \(hooked)", "load_addr: 0x\(String(loadAddr, radix: 16))",
                    ]))
            }

            // Check first page for any trampoline patterns
            anomalies.append(contentsOf:
                scanTextPage(task: task, baseAddr: loadAddr, libName: libName,
                             pid: pid, processName: name, processPath: path))
        }
        return anomalies
    }

    /// Check if the bytes at addr match a trampoline pattern.
    private func checkForTrampoline(task: mach_port_t, addr: UInt64, libName: String) -> String? {
        var instructions: (UInt32, UInt32) = (0, 0)
        var outSize: mach_vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &instructions) { ptr in
            mach_vm_read_overwrite(
                task, mach_vm_address_t(addr), 8,
                mach_vm_address_t(UInt(bitPattern: ptr)), &outSize)
        }
        guard kr == KERN_SUCCESS, outSize == 8 else { return nil }

        for (ldr, br) in trampolinePatterns {
            if instructions.0 == ldr && instructions.1 == br {
                return "LDR+BR trampoline"
            }
        }

        // Check for ADRP + BR pattern (another common hook)
        let insn0 = instructions.0
        let insn1 = instructions.1
        // ADRP: op=1, immlo=bits[30:29], immhi=bits[23:5], Rd=bits[4:0]
        // Encoding: 1|immlo|10000|immhi|Rd → top bit is 1, bits[28:24] = 10000
        let isADRP = (insn0 & 0x9F000000) == 0x90000000
        // BR: 1101_0110_0001_1111_0000_00|Rn[4:0]|00000
        let isBR = (insn1 & 0xFFFFFC1F) == 0xD61F0000
        if isADRP && isBR {
            return "ADRP+BR trampoline"
        }

        return nil
    }

    /// Scan the first page of __TEXT for trampoline patterns at function boundaries.
    /// On ARM64, function alignment is 4 bytes. We check every 4-byte aligned offset.
    private func scanTextPage(
        task: mach_port_t, baseAddr: UInt64, libName: String,
        pid: pid_t, processName: String, processPath: String
    ) -> [ProcessAnomaly] {
        // Read first 4KB (one page)
        let pageSize = 4096
        let buf = UnsafeMutableRawPointer.allocate(byteCount: pageSize, alignment: 8)
        defer { buf.deallocate() }
        var outSize: mach_vm_size_t = 0
        let kr = mach_vm_read_overwrite(
            task, mach_vm_address_t(baseAddr), mach_vm_size_t(pageSize),
            mach_vm_address_t(UInt(bitPattern: buf)), &outSize)
        guard kr == KERN_SUCCESS, outSize >= 8 else { return [] }

        var anomalies: [ProcessAnomaly] = []
        let count = Int(outSize) / 4

        // Walk instructions looking for LDR+BR pairs
        for i in stride(from: 0, to: count - 1, by: 1) {
            let insn0 = buf.advanced(by: i * 4).load(as: UInt32.self)
            let insn1 = buf.advanced(by: (i + 1) * 4).load(as: UInt32.self)

            for (ldr, br) in trampolinePatterns {
                if insn0 == ldr && insn1 == br {
                    let offset = i * 4
                    anomalies.append(.forProcess(
                        pid: pid, name: processName, path: processPath,
                        technique: "Inline Function Hook (Page Scan)",
                        description: "\(processName) has trampoline in \(libName) at offset +0x\(String(offset, radix: 16))",
                        severity: .high, mitreID: "T1574.013",
                        scannerId: "inline_hook",
                        enumMethod: "TASK_DYLD_INFO + page scan (LDR+BR pattern)",
                        evidence: [
                            "pid: \(pid)", "lib: \(libName)",
                            "offset: +0x\(String(offset, radix: 16))",
                            "addr: 0x\(String(baseAddr + UInt64(offset), radix: 16))",
                        ]))
                    break // One finding per page per lib is enough
                }
            }
            if !anomalies.isEmpty { break } // Found a hook, stop scanning this lib
        }
        return anomalies
    }

    // MARK: - Memory Read Helper

    private func readMem<T>(_ task: mach_port_t, _ addr: mach_vm_address_t,
                            _ out: inout T, _ size: Int) -> Bool {
        var outSize: mach_vm_size_t = 0
        let kr = withUnsafeMutablePointer(to: &out) { ptr in
            mach_vm_read_overwrite(
                task, addr, mach_vm_size_t(size),
                mach_vm_address_t(UInt(bitPattern: ptr)), &outSize)
        }
        return kr == KERN_SUCCESS
    }
}
