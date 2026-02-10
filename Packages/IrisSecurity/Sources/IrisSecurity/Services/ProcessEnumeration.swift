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
        return URL(fileURLWithPath: path).lastPathComponent
    }
}
