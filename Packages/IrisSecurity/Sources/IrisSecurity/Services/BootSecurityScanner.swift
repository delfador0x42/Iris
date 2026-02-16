import Foundation
import os.log

/// Scans boot chain security: NVRAM variables, Secure Boot, firmware.
/// Covers: eficheck, nvram_boot, preboot_scan, sep_coprocessor.
/// Firmware implants survive OS reinstall — critical to verify.
/// Uses IOKit + SysctlReader for NVRAM/SEP. bputil still shells out.
public actor BootSecurityScanner {
  public static let shared = BootSecurityScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "BootSecurity")

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanNVRAM())
    anomalies.append(contentsOf: await scanSecureBoot())
    anomalies.append(contentsOf: scanPrebootVolume())
    anomalies.append(contentsOf: scanSEPStatus())
    return anomalies
  }

  /// Check NVRAM for suspicious boot arguments via IOKit
  private func scanNVRAM() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let nvram = IOKitRegistryReader.nvramVariables()

    // Read boot-args (can be Data or String)
    let bootArgs: String
    if let str = nvram["boot-args"] as? String {
      bootArgs = str
    } else if let data = nvram["boot-args"] as? Data {
      bootArgs = String(data: data, encoding: .utf8) ?? ""
    } else {
      bootArgs = ""
    }

    let checks: [(pattern: String, desc: String)] = [
      ("amfi_get_out_of_my_way", "AMFI disabled via boot-args"),
      ("-v", "Verbose boot (unusual for production)"),
      ("debug", "Kernel debug mode enabled"),
      ("rootless=0", "SIP disabled via NVRAM"),
      ("kext-dev-mode", "Kext dev mode — unsigned kexts allowed"),
    ]
    for (pattern, desc) in checks where bootArgs.contains(pattern) {
      anomalies.append(.filesystem(
        name: "nvram", path: "",
        technique: "Suspicious NVRAM Setting",
        description: desc,
        severity: .high, mitreID: "T1542",
        scannerId: "boot_security",
        enumMethod: "IOKitRegistryReader.nvramVariables → boot-args inspection",
        evidence: [
          "matched_pattern=\(pattern)",
          "boot_args=\(bootArgs)",
        ]))
    }

    // Check csr-active-config (custom SIP configuration)
    if nvram["csr-active-config"] != nil {
      anomalies.append(.filesystem(
        name: "nvram", path: "",
        technique: "Suspicious NVRAM Setting",
        description: "Custom SIP configuration (csr-active-config present)",
        severity: .high, mitreID: "T1542",
        scannerId: "boot_security",
        enumMethod: "IOKitRegistryReader.nvramVariables → csr-active-config check",
        evidence: [
          "variable=csr-active-config",
          "present=true",
        ]))
    }
    return anomalies
  }

  /// Verify Secure Boot policy — bputil has no native API
  private func scanSecureBoot() async -> [ProcessAnomaly] {
    let output = await runCommand(
      "/usr/sbin/bputil", args: ["--display-all-policies"])
    if output.contains("Permissive Security")
      || output.contains("Reduced Security")
    {
      let policy = output.contains("Permissive Security") ? "Permissive" : "Reduced"
      return [.filesystem(
        name: "SecureBoot", path: "",
        technique: "Reduced Secure Boot",
        description: "Secure Boot not at Full Security",
        severity: .medium, mitreID: "T1542",
        scannerId: "boot_security",
        enumMethod: "bputil --display-all-policies → Secure Boot policy check",
        evidence: [
          "policy=\(policy) Security",
          "expected=Full Security",
        ])]
    }
    return []
  }

  /// Scan Preboot volume for unexpected modifications
  private func scanPrebootVolume() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    guard let entries = try? fm.contentsOfDirectory(
      atPath: "/System/Volumes/Preboot"
    ) else { return [] }
    let suspiciousExts = [".sh", ".py", ".dylib", ".so", ".exe"]
    for entry in entries {
      if suspiciousExts.contains(where: { entry.hasSuffix($0) }) {
        let ext = suspiciousExts.first(where: { entry.hasSuffix($0) }) ?? ""
        anomalies.append(.filesystem(
          name: entry, path: "/System/Volumes/Preboot/\(entry)",
          technique: "Suspicious Preboot File",
          description: "Unexpected file in Preboot volume: \(entry)",
          severity: .critical, mitreID: "T1542",
          scannerId: "boot_security",
          enumMethod: "FileManager.contentsOfDirectory → Preboot volume scan",
          evidence: [
            "filename=\(entry)",
            "extension=\(ext)",
            "volume=/System/Volumes/Preboot",
          ]))
      }
    }
    return anomalies
  }

  /// Check Secure Enclave status via IOKit device tree
  private func scanSEPStatus() -> [ProcessAnomaly] {
    let hasSEP = IOKitRegistryReader.entryExists(
      plane: "IODeviceTree", path: "sep")
    if !hasSEP && !SysctlReader.isVirtualMachine {
      return [.filesystem(
        name: "SEP", path: "",
        technique: "Missing Secure Enclave",
        description: "SEP not found in IORegistry",
        severity: .medium, mitreID: "T1542",
        scannerId: "boot_security",
        enumMethod: "IOKitRegistryReader.entryExists → IODeviceTree/sep lookup",
        evidence: [
          "plane=IODeviceTree",
          "path=sep",
          "is_vm=false",
        ])]
    }
    return []
  }

  /// bputil has no native API — keep this one shell-out
  private func runCommand(
    _ path: String, args: [String]
  ) async -> String {
    await withCheckedContinuation { continuation in
      let process = Process(); let pipe = Pipe()
      process.executableURL = URL(fileURLWithPath: path)
      process.arguments = args
      process.standardOutput = pipe; process.standardError = pipe
      do {
        try process.run(); process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        continuation.resume(
          returning: String(data: data, encoding: .utf8) ?? "")
      } catch { continuation.resume(returning: "") }
    }
  }
}
