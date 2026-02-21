import Darwin
import Foundation
import os.log

/// Enumerates network sockets across all processes via proc_pidfdinfo.
/// Native replacement for `lsof` — no shell-out, ~1.5ms for the full system.
/// Requires root for complete coverage; non-root skips ~20% of processes (EPERM).
public enum SocketEnumerator {
  private static let logger = Logger(subsystem: "com.wudan.iris", category: "SocketEnum")
  private static let siSize = Int32(MemoryLayout<socket_fdinfo>.size)
  private static let fdiSize = MemoryLayout<proc_fdinfo>.size

  public struct SocketEntry: Sendable {
    public let pid: pid_t
    public let processName: String
    public let proto: Int32         // IPPROTO_TCP or IPPROTO_UDP
    public let localAddress: String
    public let localPort: UInt16
    public let remoteAddress: String
    public let remotePort: UInt16
    public let tcpState: Int32      // TCP state (0 for UDP)
  }

  /// Enumerate all TCP/UDP sockets across every process.
  public static func enumerateAll() -> [SocketEntry] {
    var pidCount = proc_listallpids(nil, 0)
    guard pidCount > 0 else { return [] }
    var pids = [pid_t](repeating: 0, count: Int(pidCount) + 128)
    let bytes = proc_listallpids(&pids, Int32(pids.count * MemoryLayout<pid_t>.size))
    guard bytes > 0 else { return [] }
    let count = Int(bytes) / MemoryLayout<pid_t>.size

    let siBuf = UnsafeMutableRawPointer.allocate(byteCount: Int(siSize), alignment: 8)
    defer { siBuf.deallocate() }
    var results: [SocketEntry] = []

    for i in 0..<count {
      let pid = pids[i]
      guard pid > 0 else { continue }
      results.append(contentsOf: socketEntries(pid: pid, siBuf: siBuf))
    }
    return results
  }

  /// Enumerate sockets for a single PID.
  public static func enumerate(pid: pid_t) -> [SocketEntry] {
    let siBuf = UnsafeMutableRawPointer.allocate(byteCount: Int(siSize), alignment: 8)
    defer { siBuf.deallocate() }
    return socketEntries(pid: pid, siBuf: siBuf)
  }

  // MARK: - Private

  private static func socketEntries(pid: pid_t, siBuf: UnsafeMutableRawPointer) -> [SocketEntry] {
    let need = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
    guard need > 0 else { return [] }
    let n = Int(need) / fdiSize + 32
    let fdBuf = UnsafeMutableRawPointer.allocate(byteCount: n * fdiSize, alignment: 8)
    defer { fdBuf.deallocate() }
    let got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdBuf, Int32(n * fdiSize))
    guard got > 0 else { return [] }
    let fdCount = Int(got) / fdiSize

    var entries: [SocketEntry] = []
    var name: String?

    for j in 0..<fdCount {
      let fdType = fdBuf.advanced(by: j * fdiSize + 4).load(as: UInt32.self)
      guard fdType == UInt32(PROX_FDTYPE_SOCKET) else { continue }
      let fdNum = fdBuf.advanced(by: j * fdiSize).load(as: Int32.self)
      memset(siBuf, 0, Int(siSize))
      let sb = proc_pidfdinfo(pid, fdNum, PROC_PIDFDSOCKETINFO, siBuf, siSize)
      guard sb == siSize else { continue }

      let si = siBuf.assumingMemoryBound(to: socket_fdinfo.self)
      let fam = si.pointee.psi.soi_family
      let proto = si.pointee.psi.soi_protocol
      guard fam == AF_INET || fam == AF_INET6 else { continue }
      guard proto == Int32(IPPROTO_TCP) || proto == Int32(IPPROTO_UDP) else { continue }
      let pname = name ?? { let n = processName(pid); name = n; return n }()

      if proto == Int32(IPPROTO_TCP) {
        let tcp = si.pointee.psi.soi_proto.pri_tcp
        entries.append(tcpEntry(pid: pid, name: pname, tcp: tcp))
      } else {
        let udp = si.pointee.psi.soi_proto.pri_in
        entries.append(udpEntry(pid: pid, name: pname, udp: udp))
      }
    }
    return entries
  }

  private static func tcpEntry(pid: pid_t, name: String, tcp: tcp_sockinfo) -> SocketEntry {
    let ini = tcp.tcpsi_ini
    let (lIP, rIP) = addresses(ini: ini)
    return SocketEntry(
      pid: pid, processName: name, proto: Int32(IPPROTO_TCP),
      localAddress: lIP, localPort: nport(ini.insi_lport),
      remoteAddress: rIP, remotePort: nport(ini.insi_fport),
      tcpState: tcp.tcpsi_state)
  }

  private static func udpEntry(pid: pid_t, name: String, udp: in_sockinfo) -> SocketEntry {
    let (lIP, rIP) = addresses(ini: udp)
    return SocketEntry(
      pid: pid, processName: name, proto: Int32(IPPROTO_UDP),
      localAddress: lIP, localPort: nport(udp.insi_lport),
      remoteAddress: rIP, remotePort: nport(udp.insi_fport),
      tcpState: 0)
  }
}
