import Foundation
import os.log

/// Enumerates ALL tasks in the system via Mach processor_set_tasks().
/// This is the deepest possible process enumeration on macOS —
/// walks task ports directly from the kernel. Catches processes hidden
/// from sysctl(KERN_PROC_ALL) and even from kill(pid,0) brute-force.
/// Requires root (UID 0) for host_processor_set_priv().
public enum MachTaskEnumerator {
    private static let logger = Logger(subsystem: "com.wudan.iris", category: "MachTaskEnum")

    /// A task discovered via Mach port enumeration.
    public struct MachTask: Sendable {
        public let pid: pid_t
        public let path: String
        public let name: String
    }

    /// Enumerate every task in the system via processor_set_tasks().
    /// Returns empty array if not running as root.
    public static func enumerateAll() -> [MachTask] {
        let host = mach_host_self()
        defer { mach_port_deallocate(mach_task_self_, host) }

        // Step 1: Get default processor set name port
        var psetName: processor_set_name_t = 0
        var kr = processor_set_default(host, &psetName)
        guard kr == KERN_SUCCESS else {
            logger.warning("processor_set_default failed: \(kr)")
            return []
        }

        // Step 2: Upgrade to privileged control port (requires root)
        var psetPriv: processor_set_t = 0
        kr = host_processor_set_priv(host, psetName, &psetPriv)
        mach_port_deallocate(mach_task_self_, psetName)
        guard kr == KERN_SUCCESS else {
            logger.info("host_processor_set_priv failed: \(kr) (not root?)")
            return []
        }

        // Step 3: Get ALL task ports
        var tasks: task_array_t?
        var taskCount: mach_msg_type_number_t = 0
        kr = processor_set_tasks(psetPriv, &tasks, &taskCount)
        mach_port_deallocate(mach_task_self_, psetPriv)
        guard kr == KERN_SUCCESS, let taskArray = tasks else {
            logger.warning("processor_set_tasks failed: \(kr)")
            return []
        }

        // Step 4: Convert task ports to PIDs
        var results: [MachTask] = []
        results.reserveCapacity(Int(taskCount))

        for i in 0..<Int(taskCount) {
            let task = taskArray[i]
            var pid: Int32 = -1
            pid_for_task(task, &pid)
            mach_port_deallocate(mach_task_self_, task)
            guard pid >= 0 else { continue }
            let path = pidPath(pid)
            let name = path.isEmpty ? pidName(pid) : URL(fileURLWithPath: path).lastPathComponent
            results.append(MachTask(pid: pid, path: path, name: name))
        }

        // Step 5: Deallocate the OOL task array
        let arraySize = mach_vm_size_t(taskCount) * mach_vm_size_t(MemoryLayout<task_t>.size)
        mach_vm_deallocate(
            mach_task_self_,
            mach_vm_address_t(Int(bitPattern: UnsafeRawPointer(taskArray))),
            arraySize
        )

        logger.info("Mach enumeration: \(results.count) tasks")
        return results
    }

    /// Get PIDs only (for fast set comparison)
    public static func enumeratePIDs() -> Set<pid_t> {
        Set(enumerateAll().map(\.pid))
    }

    // MARK: - Helpers

    private static func pidPath(_ pid: pid_t) -> String {
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let r = proc_pidpath(pid, &buf, UInt32(MAXPATHLEN))
        guard r > 0 else { return "" }
        return String(cString: buf)
    }

    private static func pidName(_ pid: pid_t) -> String {
        var info = proc_bsdinfo()
        let size = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        guard size > 0 else { return "unknown" }
        return withUnsafeBytes(of: info.pbi_name) { buf in
            String(cString: buf.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
    }
}
