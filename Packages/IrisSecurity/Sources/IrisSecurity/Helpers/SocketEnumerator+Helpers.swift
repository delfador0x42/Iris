import Darwin
import Foundation

extension SocketEnumerator {
  /// Convert network-byte-order port (stored as Int32) to host UInt16.
  /// ntohs() is a C macro unavailable in Swift — manual byte swap.
  static func nport(_ p: Int32) -> UInt16 {
    UInt16(truncatingIfNeeded: p & 0xFFFF).bigEndian
  }

  /// Extract local/remote IP strings from in_sockinfo.
  static func addresses(ini: in_sockinfo) -> (local: String, remote: String) {
    let vf = ini.insi_vflag
    if vf & UInt8(INI_IPV4) != 0 {
      return (
        ip4(ini.insi_laddr.ina_46.i46a_addr4),
        ip4(ini.insi_faddr.ina_46.i46a_addr4)
      )
    } else if vf & UInt8(INI_IPV6) != 0 {
      return (
        ip6(ini.insi_laddr.ina_6),
        ip6(ini.insi_faddr.ina_6)
      )
    }
    return ("*", "*")
  }

  static func ip4(_ addr: in_addr) -> String {
    var a = addr
    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    inet_ntop(AF_INET, &a, &buf, socklen_t(INET_ADDRSTRLEN))
    return String(cString: buf)
  }

  static func ip6(_ addr: in6_addr) -> String {
    var a = addr
    var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    inet_ntop(AF_INET6, &a, &buf, socklen_t(INET6_ADDRSTRLEN))
    return String(cString: buf)
  }

  static func processName(_ pid: pid_t) -> String {
    var buf = [CChar](repeating: 0, count: Int(MAXCOMLEN) + 1)
    let r = proc_name(pid, &buf, UInt32(buf.count))
    if r > 0 {
      let s = String(cString: buf)
      if !s.isEmpty { return s }
    }
    var pathBuf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    let r2 = proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
    guard r2 > 0 else { return "unknown" }
    return URL(fileURLWithPath: String(cString: pathBuf)).lastPathComponent
  }
}
