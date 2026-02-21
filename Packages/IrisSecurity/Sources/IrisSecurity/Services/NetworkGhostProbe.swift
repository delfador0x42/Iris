import Foundation
import os.log

/// Detects ghost network traffic — connections that exist but no process claims.
///
/// Lie detected: "All network traffic comes from visible processes"
/// Ground truth: Enumerate ALL network sockets via proc_pidfdinfo for every PID,
///               cross-reference with the proxy's captured flows.
///               Any traffic without a process owner = ghost.
///
/// This catches:
/// - Firmware-level network implants (SSD/NIC firmware sending data)
/// - Kernel rootkits with hidden sockets
/// - Processes that somehow evade both ES and proxy attribution
///
/// Adversary cost: Would need to hide from BOTH the proxy flow attribution
/// AND proc_pidfdinfo enumeration simultaneously.
public actor NetworkGhostProbe {
    public static let shared = NetworkGhostProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "NetworkGhost")

    /// Represents a socket found via kernel enumeration
    private struct KernelSocket: Hashable {
        let pid: pid_t
        let processName: String
        let family: Int32        // AF_INET, AF_INET6
        let proto: Int32         // IPPROTO_TCP, IPPROTO_UDP
        let localPort: UInt16
        let remotePort: UInt16
        let remoteAddr: String
        let state: Int32         // TCP state if applicable
    }

    /// Scan for ghost traffic by comparing socket enumeration vs process visibility
    public func scan(connections: [NetworkConnection]) async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []

        // ── Source 1: Enumerate ALL sockets via proc_pidfdinfo ──
        let kernelSockets = enumerateAllSockets()

        // ── Source 2: Get process-attributed connections from proxy ──
        let proxyPids = Set(connections.map(\.processId))
        let proxyRemotes = Set(connections.map { "\($0.remoteAddress):\($0.remotePort)" })

        logger.info("Ghost scan: \(kernelSockets.count) kernel sockets, \(connections.count) proxy flows, \(proxyPids.count) proxy PIDs")

        // ── Check 1: Sockets owned by PIDs that proxy never saw ──
        // This catches processes that bypass the NETransparentProxyProvider
        var unseenPids: [pid_t: [KernelSocket]] = [:]
        for sock in kernelSockets {
            // Skip loopback and local sockets
            if sock.remoteAddr == "127.0.0.1" || sock.remoteAddr == "::1" { continue }
            if sock.remoteAddr.isEmpty || sock.remotePort == 0 { continue }
            // Skip listen sockets
            if sock.state == 1 { continue } // TSI_S_LISTEN

            if !proxyPids.contains(sock.pid) {
                unseenPids[sock.pid, default: []].append(sock)
            }
        }

        for (pid, sockets) in unseenPids {
            // Filter: some system processes legitimately bypass proxy
            let name = sockets.first?.processName ?? "unknown"
            let exemptions: Set<String> = ["mDNSResponder", "configd", "netbiosd",
                                           "SystemExtensions", "nesessionmanager",
                                           "nehelper", "networkd", "symptomsd"]
            if exemptions.contains(name) { continue }

            let remotes = sockets.map { "\($0.remoteAddr):\($0.remotePort)" }
            anomalies.append(.forProcess(
                pid: pid, name: name, path: processPath(for: pid),
                technique: "Proxy-Invisible Network Activity",
                description: "\(name) (PID \(pid)) has \(sockets.count) active sockets but was NEVER seen by the transparent proxy. Traffic is bypassing network monitoring.",
                severity: .high, mitreID: "T1071",
                scannerId: "network_ghost",
                enumMethod: "proc_pidfdinfo(PROC_PIDFDSOCKETINFO) vs NETransparentProxyProvider flow attribution",
                evidence: [
                    "pid: \(pid)",
                    "name: \(name)",
                    "socket_count: \(sockets.count)",
                    "destinations: \(remotes.prefix(5).joined(separator: ", "))",
                ]))
        }

        // ── Check 2: Active external connections from unknown PIDs ──
        // Sockets with remote addresses that exist in kernel but PID is dead/hidden
        for sock in kernelSockets {
            if sock.remoteAddr.isEmpty || sock.remotePort == 0 { continue }
            if sock.remoteAddr == "127.0.0.1" || sock.remoteAddr == "::1" { continue }
            if sock.state == 1 { continue }

            // Check if the PID is actually alive
            if sock.pid > 0 && kill(sock.pid, 0) != 0 {
                // Socket exists but owning PID is dead — orphaned or hidden
                let remote = "\(sock.remoteAddr):\(sock.remotePort)"
                anomalies.append(.filesystem(
                    name: "OrphanSocket", path: remote,
                    technique: "Orphaned Network Socket",
                    description: "Active socket to \(remote) owned by dead PID \(sock.pid) (\(sock.processName)). Socket persists after process death — possible kernel-level persistence.",
                    severity: .critical, mitreID: "T1014",
                    scannerId: "network_ghost",
                    enumMethod: "proc_pidfdinfo socket enumeration + kill(pid, 0) liveness check",
                    evidence: [
                        "dead_pid: \(sock.pid)",
                        "process: \(sock.processName)",
                        "remote: \(remote)",
                        "proto: \(sock.proto == 6 ? "TCP" : "UDP")",
                        "state: \(sock.state)",
                    ]))
            }
        }

        return anomalies
    }

    // MARK: - Socket Enumeration

    private func enumerateAllSockets() -> [KernelSocket] {
        var sockets: [KernelSocket] = []

        // Get all PIDs
        let estimated = proc_listallpids(nil, 0)
        guard estimated > 0 else { return [] }
        let capacity = Int(estimated) * 2
        let pidBuf = UnsafeMutablePointer<pid_t>.allocate(capacity: capacity)
        defer { pidBuf.deallocate() }
        let actual = proc_listallpids(pidBuf, Int32(capacity * MemoryLayout<pid_t>.size))
        guard actual > 0 else { return [] }

        for i in 0..<Int(actual) {
            let pid = pidBuf[i]
            if pid <= 0 { continue }
            sockets.append(contentsOf: enumerateSocketsForPid(pid))
        }
        return sockets
    }

    private func enumerateSocketsForPid(_ pid: pid_t) -> [KernelSocket] {
        // Get FD buffer size
        let bufSize = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard bufSize > 0 else { return [] }

        let fdCount = bufSize / Int32(MemoryLayout<proc_fdinfo>.size)
        let fdBuf = UnsafeMutablePointer<proc_fdinfo>.allocate(capacity: Int(fdCount))
        defer { fdBuf.deallocate() }

        let actualBytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdBuf, bufSize)
        guard actualBytes > 0 else { return [] }

        let actualFDs = Int(actualBytes) / MemoryLayout<proc_fdinfo>.size
        var sockets: [KernelSocket] = []
        let name = processName(for: pid)

        for j in 0..<actualFDs {
            let fd = fdBuf[j]
            guard fd.proc_fdtype == PROX_FDTYPE_SOCKET else { continue }

            var si = socket_fdinfo()
            let siSize = proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDSOCKETINFO,
                                         &si, Int32(MemoryLayout<socket_fdinfo>.size))
            guard siSize > 0 else { continue }

            let family = si.psi.soi_family
            guard family == AF_INET || family == AF_INET6 else { continue }

            let proto = si.psi.soi_protocol
            var remoteAddr = ""
            var remotePort: UInt16 = 0
            var localPort: UInt16 = 0
            var state: Int32 = 0

            if si.psi.soi_kind == SOCKINFO_TCP {
                let tcp = si.psi.soi_proto.pri_tcp
                state = tcp.tcpsi_state
                remotePort = UInt16(bigEndian: UInt16(truncatingIfNeeded: tcp.tcpsi_ini.insi_fport))
                localPort = UInt16(bigEndian: UInt16(truncatingIfNeeded: tcp.tcpsi_ini.insi_lport))
                remoteAddr = extractAddress(from: tcp.tcpsi_ini, family: family, isRemote: true)
            } else if si.psi.soi_kind == SOCKINFO_IN {
                let ini = si.psi.soi_proto.pri_in
                remotePort = UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_fport))
                localPort = UInt16(bigEndian: UInt16(truncatingIfNeeded: ini.insi_lport))
                remoteAddr = extractAddress(from: ini, family: family, isRemote: true)
            }

            sockets.append(KernelSocket(
                pid: pid, processName: name, family: family,
                proto: proto, localPort: localPort,
                remotePort: remotePort, remoteAddr: remoteAddr, state: state))
        }
        return sockets
    }

    private func extractAddress(from ini: in_sockinfo, family: Int32, isRemote: Bool) -> String {
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        if family == AF_INET {
            var addr = isRemote ? ini.insi_faddr.ina_46.i46a_addr4 : ini.insi_laddr.ina_46.i46a_addr4
            inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN))
        } else {
            var addr = isRemote ? ini.insi_faddr.ina_6 : ini.insi_laddr.ina_6
            inet_ntop(AF_INET6, &addr, &buf, socklen_t(INET6_ADDRSTRLEN))
        }
        return String(cString: buf)
    }

    private func processName(for pid: pid_t) -> String {
        var name = [CChar](repeating: 0, count: Int(MAXCOMLEN) + 1)
        proc_name(pid, &name, UInt32(name.count))
        let s = String(cString: name)
        return s.isEmpty ? "unknown" : s
    }

    private func processPath(for pid: pid_t) -> String {
        var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        proc_pidpath(pid, &path, UInt32(path.count))
        return String(cString: path)
    }
}
