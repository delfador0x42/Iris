import Foundation

/// Shared process enumeration helpers used by all scanners.
/// Eliminates 6-8 duplicate implementations of the same syscall wrappers.
enum ProcessEnumeration {

    /// List all running PIDs on the system
    static func getRunningPIDs() -> [pid_t] {
        let bufSize = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
        guard bufSize > 0 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(bufSize) / MemoryLayout<pid_t>.size)
        let actual = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pids, bufSize)
        guard actual > 0 else { return [] }
        return Array(pids.prefix(Int(actual) / MemoryLayout<pid_t>.size)).filter { $0 > 0 }
    }

    /// Get executable path for a PID via proc_pidpath
    static func getProcessPath(_ pid: pid_t) -> String {
        let buf = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(MAXPATHLEN))
        defer { buf.deallocate() }
        let len = proc_pidpath(pid, buf, UInt32(MAXPATHLEN))
        guard len > 0 else { return "" }
        return String(cString: buf)
    }

    /// Get parent PID via proc_pidinfo PROC_PIDTBSDINFO
    static func getParentPID(_ pid: pid_t) -> pid_t {
        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard size > 0 else { return 0 }
        return pid_t(info.pbi_ppid)
    }

    /// Get process name from its path
    static func getProcessName(_ pid: pid_t) -> String {
        let path = getProcessPath(pid)
        guard !path.isEmpty else { return "unknown" }
        return (path as NSString).lastPathComponent
    }

    /// Get command-line arguments for a PID via KERN_PROCARGS2.
    /// Format: [4-byte argc][exec path \0][padding \0s][arg0 \0][arg1 \0]...
    static func getProcessArguments(_ pid: pid_t) -> [String] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0,
              size > MemoryLayout<Int32>.size else { return [] }

        let argc: Int32 = buffer.withUnsafeBufferPointer {
            $0.baseAddress!.withMemoryRebound(to: Int32.self, capacity: 1) { $0.pointee }
        }
        guard argc > 0, argc < 512 else { return [] }

        var offset = MemoryLayout<Int32>.size
        // Skip executable path
        while offset < size && buffer[offset] != 0 { offset += 1 }
        // Skip null padding
        while offset < size && buffer[offset] == 0 { offset += 1 }

        var args: [String] = []
        while args.count < Int(argc) && offset < size {
            let start = offset
            while offset < size && buffer[offset] != 0 { offset += 1 }
            if offset > start,
               let arg = String(bytes: buffer[start..<offset], encoding: .utf8) {
                args.append(arg)
            }
            offset += 1
        }
        return args
    }

    /// Get environment variables for a PID via KERN_PROCARGS2.
    /// Returns all env vars after the command-line arguments.
    static func getProcessEnvironment(_ pid: pid_t) -> [(key: String, value: String)] {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size: Int = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 0 else { return [] }

        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0,
              size > MemoryLayout<Int32>.size else { return [] }

        let argc: Int32 = buffer.withUnsafeBufferPointer {
            $0.baseAddress!.withMemoryRebound(to: Int32.self, capacity: 1) { $0.pointee }
        }
        guard argc > 0, argc < 512 else { return [] }

        var offset = MemoryLayout<Int32>.size
        // Skip executable path
        while offset < size && buffer[offset] != 0 { offset += 1 }
        // Skip null padding
        while offset < size && buffer[offset] == 0 { offset += 1 }

        // Skip arguments
        var argsSkipped = 0
        while argsSkipped < Int(argc) && offset < size {
            while offset < size && buffer[offset] != 0 { offset += 1 }
            offset += 1
            argsSkipped += 1
        }

        // Parse environment variables (KEY=VALUE\0 format)
        var envVars: [(key: String, value: String)] = []
        while offset < size {
            let start = offset
            while offset < size && buffer[offset] != 0 { offset += 1 }
            guard offset > start else { break }
            if let entry = String(bytes: buffer[start..<offset], encoding: .utf8),
               let eqIdx = entry.firstIndex(of: "=") {
                let key = String(entry[entry.startIndex..<eqIdx])
                let value = String(entry[entry.index(after: eqIdx)...])
                envVars.append((key: key, value: value))
            }
            offset += 1
        }
        return envVars
    }
}
