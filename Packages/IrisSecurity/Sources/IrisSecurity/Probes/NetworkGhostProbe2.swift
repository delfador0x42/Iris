import Foundation
import os.log

/// Detects ghost network traffic — connections that exist but no process claims.
/// Compares kernel socket enumeration via proc_pidfdinfo against proxy flow attribution.
public actor NetworkGhostProbe2: ContradictionProbe {
    public static let shared = NetworkGhostProbe2()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "NetworkGhost2")

    public nonisolated let id = "network-ghost"
    public nonisolated let name = "Network Ghost Detection"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "All network traffic comes from visible, attributed processes",
        groundTruth: "Enumerate ALL sockets via proc_pidfdinfo for every PID, cross-reference with proxy's captured flows and verify owning PIDs are alive",
        adversaryCost: "Must hide from BOTH proc_pidfdinfo socket enumeration AND transparent proxy flow attribution simultaneously",
        positiveDetection: "Shows unattributed sockets with remote destinations and owning PID status",
        falsePositiveRate: "Low — system processes exempt, only flags external connections from unknown sources"
    )

    private struct KernelSocket: Hashable {
        let pid: pid_t
        let processName: String
        let family: Int32
        let proto: Int32
        let localPort: UInt16
        let remotePort: UInt16
        let remoteAddr: String
        let state: Int32
    }

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        let kernelSockets = enumerateAllSockets()
        let connections = await MainActor.run { SecurityStore.shared.connections }
        let proxyPids = Set(connections.map(\.processId))

        // Exemptions — system processes that legitimately bypass proxy
        let exemptions: Set<String> = [
            "mDNSResponder", "configd", "netbiosd", "SystemExtensions",
            "nesessionmanager", "nehelper", "networkd", "symptomsd",
        ]

        // Check 1: Sockets from PIDs the proxy never saw
        var unseenPids: [pid_t: [KernelSocket]] = [:]
        for sock in kernelSockets {
            if sock.remoteAddr == "127.0.0.1" || sock.remoteAddr == "::1" { continue }
            if sock.remoteAddr.isEmpty || sock.remotePort == 0 { continue }
            if sock.state == 1 { continue }  // LISTEN
            if exemptions.contains(sock.processName) { continue }
            if !proxyPids.contains(sock.pid) {
                unseenPids[sock.pid, default: []].append(sock)
            }
        }

        for (pid, sockets) in unseenPids {
            hasContradiction = true
            let name = sockets.first?.processName ?? "unknown"
            let remotes = sockets.prefix(3).map { "\($0.remoteAddr):\($0.remotePort)" }
            comparisons.append(SourceComparison(
                label: "\(name) (PID \(pid)): proxy visibility",
                sourceA: SourceValue("kernel sockets", "\(sockets.count) active connections to \(remotes.joined(separator: ", "))"),
                sourceB: SourceValue("proxy flows", "never seen"),
                matches: false))
        }

        // Check 2: Orphaned sockets — owning PID is dead
        for sock in kernelSockets {
            if sock.remoteAddr.isEmpty || sock.remotePort == 0 { continue }
            if sock.remoteAddr == "127.0.0.1" || sock.remoteAddr == "::1" { continue }
            if sock.state == 1 { continue }
            if sock.pid > 0 && kill(sock.pid, 0) != 0 {
                hasContradiction = true
                comparisons.append(SourceComparison(
                    label: "orphaned socket to \(sock.remoteAddr):\(sock.remotePort)",
                    sourceA: SourceValue("socket owner", "PID \(sock.pid) (\(sock.processName))"),
                    sourceB: SourceValue("process liveness", "DEAD (kill(pid,0) failed)"),
                    matches: false))
            }
        }

        // Summary comparison
        comparisons.insert(SourceComparison(
            label: "socket/proxy coverage",
            sourceA: SourceValue("kernel sockets", "\(kernelSockets.count) total"),
            sourceB: SourceValue("proxy flows", "\(connections.count) attributed"),
            matches: unseenPids.isEmpty), at: 0)

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)
        let verdict: ProbeVerdict
        let message: String

        if hasContradiction {
            let ghosts = unseenPids.count
            let orphans = comparisons.filter { $0.label.hasPrefix("orphaned") }.count
            verdict = .contradiction
            message = "CONTRADICTION: \(ghosts) proxy-invisible process(es), \(orphans) orphaned socket(s)"
        } else {
            verdict = .consistent
            message = "All \(kernelSockets.count) sockets attributed to known processes"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Socket Enumeration

    private func enumerateAllSockets() -> [KernelSocket] {
        var sockets: [KernelSocket] = []
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
}
