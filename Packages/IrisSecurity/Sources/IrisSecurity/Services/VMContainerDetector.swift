import Foundation
import os.log

/// Detects hidden virtual machines and containers.
/// Docker, Podman, Lima, UTM, Parallels, VMware, QEMU.
/// Adversaries use VMs for: isolated C2, lateral movement, credential harvesting.
public actor VMContainerDetector {
  public static let shared = VMContainerDetector()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "VMContainer")

  /// Known VM/container process names
  private static let vmProcesses: [(name: String, type: String)] = [
    ("qemu-system", "QEMU VM"), ("VBoxHeadless", "VirtualBox"),
    ("vmware-vmx", "VMware"), ("prl_vm_app", "Parallels"),
    ("UTMQemu", "UTM"), ("com.docker.vmnetd", "Docker"),
    ("containerd", "Container Runtime"), ("dockerd", "Docker Daemon"),
    ("podman", "Podman"), ("lima", "Lima"), ("colima", "Colima"),
    ("nerdctl", "Nerdctl"), ("crc", "OpenShift Local"),
  ]

  /// Known VM/container socket and config paths
  private static let vmPaths = [
    "/var/run/docker.sock", "/var/run/containerd/containerd.sock",
    "~/.docker/", "~/.lima/", "~/.colima/",
    "~/.parallels/", "/Applications/UTM.app",
    "/Applications/VMware Fusion.app", "/Applications/Parallels Desktop.app",
  ]

  public func scan(snapshot: ProcessSnapshot) async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanRunningVMs(snapshot: snapshot))
    anomalies.append(contentsOf: scanVMPaths())
    anomalies.append(contentsOf: await scanDockerContainers())
    return anomalies
  }

  /// Check for VM/container processes
  private func scanRunningVMs(snapshot: ProcessSnapshot) -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    for pid in snapshot.pids {
      let procName = snapshot.name(for: pid)
      let procPath = snapshot.path(for: pid)
      for (name, vmType) in Self.vmProcesses {
        if procName.contains(name) || procPath.contains(name) {
          anomalies.append(.forProcess(
            pid: pid, name: procName, path: procPath,
            technique: "Virtual Machine/Container Running",
            description: "\(vmType) detected: \(procName) (PID \(pid))",
            severity: .low, mitreID: "T1564.006",
            scannerId: "vm_container",
            enumMethod: "ProcessSnapshot → VM/container process name match",
            evidence: [
              "pid=\(pid)",
              "vm_type=\(vmType)",
              "matched_name=\(name)",
            ]
          ))
        }
      }
    }
    return anomalies
  }

  /// Check for VM infrastructure on disk
  private func scanVMPaths() -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let fm = FileManager.default
    let home = NSHomeDirectory()
    for path in Self.vmPaths {
      let resolved = path.replacingOccurrences(of: "~", with: home)
      if fm.fileExists(atPath: resolved) {
        anomalies.append(.filesystem(
          name: URL(fileURLWithPath: resolved).lastPathComponent, path: resolved,
          technique: "VM/Container Infrastructure",
          description: "VM/container artifact found: \(resolved)",
          severity: .low, mitreID: "T1564.006",
          scannerId: "vm_container",
          enumMethod: "FileManager.fileExists → known VM path check",
          evidence: [
            "path=\(resolved)",
            "original_pattern=\(path)",
          ]
        ))
      }
    }
    return anomalies
  }

  /// List running Docker containers
  private func scanDockerContainers() async -> [ProcessAnomaly] {
    guard FileManager.default.fileExists(atPath: "/usr/local/bin/docker") ||
      FileManager.default.fileExists(atPath: "/opt/homebrew/bin/docker")
    else { return [] }
    let output = await runCommand("/usr/bin/env", args: ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}"])
    var anomalies: [ProcessAnomaly] = []
    for line in output.components(separatedBy: "\n") where !line.isEmpty {
      let parts = line.components(separatedBy: "\t")
      let name = parts.first ?? line
      anomalies.append(.filesystem(
        name: name, path: "docker",
        technique: "Running Docker Container",
        description: "Container: \(line)",
        severity: .low, mitreID: "T1564.006",
        scannerId: "vm_container",
        enumMethod: "docker ps → running container enumeration",
        evidence: [
          "container_name=\(name)",
          "full_line=\(line)",
        ]
      ))
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
