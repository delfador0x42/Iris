import Foundation
import os.log

/// Scans boot chain security: NVRAM variables, Secure Boot, firmware.
/// Covers: eficheck, nvram_boot, preboot_scan, sep_coprocessor hunt scripts.
/// Firmware implants survive OS reinstall — critical to verify.
public actor BootSecurityScanner {
  public static let shared = BootSecurityScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "BootSecurity")

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: await scanNVRAM())
    anomalies.append(contentsOf: await scanSecureBoot())
    anomalies.append(contentsOf: await scanPrebootVolume())
    anomalies.append(contentsOf: await scanSEPStatus())
    return anomalies
  }

  /// Check NVRAM for suspicious boot arguments
  private func scanNVRAM() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand("/usr/sbin/nvram", args: ["-p"])
    let suspiciousArgs: [(pattern: String, desc: String)] = [
      ("boot-args.*amfi_get_out_of_my_way", "AMFI disabled via boot-args"),
      ("boot-args.*-v", "Verbose boot (unusual for production)"),
      ("boot-args.*debug", "Kernel debug mode enabled"),
      ("boot-args.*rootless=0", "SIP disabled via NVRAM"),
      ("boot-args.*kext-dev-mode", "Kext dev mode — unsigned kexts allowed"),
      ("csr-active-config", "Custom SIP configuration"),
    ]
    for (pattern, desc) in suspiciousArgs {
      if output.range(of: pattern, options: .regularExpression) != nil {
        anomalies.append(.filesystem(
          name: "nvram", path: "",
          technique: "Suspicious NVRAM Setting",
          description: desc,
          severity: .high, mitreID: "T1542"
        ))
      }
    }
    return anomalies
  }

  /// Verify Secure Boot policy status
  private func scanSecureBoot() async -> [ProcessAnomaly] {
    let output = await runCommand(
      "/usr/sbin/bputil", args: ["--display-all-policies"])
    if output.contains("Permissive Security") || output.contains("Reduced Security") {
      return [.filesystem(
        name: "SecureBoot", path: "",
        technique: "Reduced Secure Boot",
        description: "Secure Boot is not at Full Security — boot chain less protected",
        severity: .medium, mitreID: "T1542"
      )]
    }
    return []
  }

  /// Scan Preboot volume for unexpected modifications
  private func scanPrebootVolume() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let prebootPath = "/System/Volumes/Preboot"
    let fm = FileManager.default
    guard let entries = try? fm.contentsOfDirectory(atPath: prebootPath) else { return [] }
    for entry in entries {
      let fullPath = "\(prebootPath)/\(entry)"
      // Check for non-standard files in Preboot
      if entry.hasSuffix(".sh") || entry.hasSuffix(".py") || entry.hasSuffix(".dylib") {
        anomalies.append(.filesystem(
          name: entry, path: fullPath,
          technique: "Suspicious Preboot File",
          description: "Unexpected file in Preboot volume: \(entry)",
          severity: .critical, mitreID: "T1542"
        ))
      }
    }
    return anomalies
  }

  /// Check Secure Enclave / coprocessor status via IORegistry
  private func scanSEPStatus() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let output = await runCommand(
      "/usr/sbin/ioreg", args: ["-l", "-p", "IODeviceTree", "-n", "sep"])
    if output.isEmpty {
      // No SEP in IORegistry — may be a VM or tampered system
      let hwOutput = await runCommand(
        "/usr/sbin/sysctl", args: ["-n", "hw.model"])
      if !hwOutput.contains("Virtual") {
        anomalies.append(.filesystem(
          name: "SEP", path: "",
          technique: "Missing Secure Enclave",
          description: "SEP not found in IORegistry — hardware integrity concern",
          severity: .medium, mitreID: "T1542"
        ))
      }
    }
    return anomalies
  }

  private func runCommand(_ path: String, args: [String]) async -> String {
    await withCheckedContinuation { continuation in
      let process = Process(); let pipe = Pipe()
      process.executableURL = URL(fileURLWithPath: path)
      process.arguments = args
      process.standardOutput = pipe; process.standardError = pipe
      do {
        try process.run(); process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        continuation.resume(returning: String(data: data, encoding: .utf8) ?? "")
      } catch { continuation.resume(returning: "") }
    }
  }
}
