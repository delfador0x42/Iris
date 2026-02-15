import Darwin

/// Native sysctl access — replaces shell-outs to /usr/sbin/sysctl.
/// Direct sysctlbyname() calls are ~1000x faster than Process().
public enum SysctlHelper {

  /// Read a sysctl string value (e.g. "hw.model", "kern.osversion").
  public static func string(_ name: String) -> String? {
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
    var buffer = [CChar](repeating: 0, count: size)
    guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
    return String(cString: buffer)
  }

  /// Read a sysctl integer value (e.g. "kern.hv_vmm_present").
  public static func int32(_ name: String) -> Int32? {
    var value: Int32 = 0
    var size = MemoryLayout<Int32>.size
    guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
    return value
  }

  /// Read a sysctl Int64 value.
  public static func int64(_ name: String) -> Int64? {
    var value: Int64 = 0
    var size = MemoryLayout<Int64>.size
    guard sysctlbyname(name, &value, &size, nil, 0) == 0 else { return nil }
    return value
  }

  /// Read raw bytes from sysctl (e.g. for "security.mac" MACF policy list).
  public static func data(_ name: String) -> Data? {
    var size = 0
    guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
    var buffer = [UInt8](repeating: 0, count: size)
    guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else { return nil }
    return Data(buffer[0..<size])
  }

  /// Check if running under hypervisor.
  public static var isVirtualMachine: Bool {
    (int32("kern.hv_vmm_present") ?? 0) != 0
  }

  /// Hardware model string (e.g. "Mac14,2").
  public static var hwModel: String? { string("hw.model") }

  /// Number of CPUs.
  public static var cpuCount: Int32? { int32("hw.ncpu") }

  /// Physical memory in bytes.
  public static var physicalMemory: Int64? { int64("hw.memsize") }

  /// OS version string.
  public static var osVersion: String? { string("kern.osversion") }
}
