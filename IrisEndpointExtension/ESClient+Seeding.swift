import Foundation
import EndpointSecurity
import os.log

/// Process table seeding and noise muting for ESClient.
/// Seeding captures all running processes at extension startup via sysctl.
/// Muting reduces event volume from known high-noise system daemons.
extension ESClient {

    // MARK: - Process Table Seeding

    /// Populate processTable with all currently running processes via sysctl.
    /// Called once at startup so the app has a complete snapshot immediately.
    func seedProcessTable() {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size: Int = 0

        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else {
            logger.warning("Failed to get process list size for seeding")
            return
        }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var procList = [kinfo_proc](repeating: kinfo_proc(), count: count)

        guard sysctl(&mib, 4, &procList, &size, nil, 0) == 0 else {
            logger.warning("Failed to get process list for seeding")
            return
        }

        let actualCount = size / MemoryLayout<kinfo_proc>.stride
        var seeded = 0

        processLock.lock()
        for i in 0..<actualCount {
            let proc = procList[i]
            let pid = proc.kp_proc.p_pid
            guard pid > 0 else { continue }

            let path = getProcessPath(pid)
            guard !path.isEmpty else { continue }

            let name = URL(fileURLWithPath: path).lastPathComponent
            let ppid = proc.kp_eproc.e_ppid
            let uid = proc.kp_eproc.e_ucred.cr_uid
            let gid = proc.kp_eproc.e_pcred.p_rgid
            let csInfo = getCodeSigningInfoForPath(path)
            let rpid = es_responsibility_get_pid_responsible_for_pid(pid)
            let responsiblePid: Int32 = (rpid > 0 && rpid != pid) ? rpid : 0

            processTable[pid] = ESProcessInfo(
                pid: pid, ppid: ppid, responsiblePid: responsiblePid,
                path: path, name: name,
                arguments: [], userId: uid, groupId: gid,
                codeSigningInfo: csInfo, timestamp: Date()
            )
            seeded += 1
        }
        processLock.unlock()

        logger.info("Seeded process table with \(seeded) existing processes")
    }

    // MARK: - Noise Muting

    /// Mute known high-noise system paths to reduce event volume.
    /// These executables spawn/fork frequently as part of normal OS operation.
    /// They're still captured in the initial seed, just not re-reported on every exec.
    func muteNoisyPaths(_ client: OpaquePointer) {
        let noisyPaths = [
            "/usr/libexec/xpcproxy",
            "/usr/libexec/runningboardd",
            "/usr/sbin/cfprefsd",
            "/usr/libexec/trustd",
            "/usr/libexec/securityd",
            "/usr/libexec/opendirectoryd",
        ]
        for path in noisyPaths {
            let result = es_mute_path_literal(client, path)
            if result == ES_RETURN_SUCCESS {
                logger.debug("[ES] Muted path: \(path)")
            }
        }
        logger.info("[ES] Muted \(noisyPaths.count) noisy system paths")
    }
}
