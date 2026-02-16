import Foundation
import os.log

/// Scans for suspicious USB devices that may be implants.
/// USB implants masquerade as chargers but have data endpoints.
/// Uses native IOKit framework — no shell-outs.
public actor USBDeviceScanner {
  public static let shared = USBDeviceScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "USBScanner")

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    anomalies.append(contentsOf: scanUSBDevices())
    anomalies.append(contentsOf: scanExternalVolumes())
    return anomalies
  }

  /// Check USB devices for implant characteristics via IOKit
  private func scanUSBDevices() -> [ProcessAnomaly] {
    var result: [ProcessAnomaly] = []
    let devices = IOKitRegistryReader.usbDevices()

    let suspicious = [
      "BadUSB", "Rubber Ducky", "USB Armory", "LAN Turtle",
      "Bash Bunny", "WiFi Pineapple", "O.MG Cable",
    ]

    for device in devices {
      let name = device["USB Product Name"] as? String
        ?? device["IOClass"] as? String ?? "Unknown USB"

      // Billboard devices claim charging-only but may have data
      if name.contains("Billboard") || device["bDeviceClass"] as? Int == 17 {
        let endpoints = device["bNumEndpoints"] as? Int ?? 0
        if endpoints > 0 {
          result.append(.filesystem(
            name: String(name.prefix(60)), path: "ioreg:IOUSB",
            technique: "USB Implant Suspect",
            description: "Billboard USB with \(endpoints) data endpoint(s)",
            severity: .high, mitreID: "T1200",
            scannerId: "usb",
            enumMethod: "IOKit → IOServiceMatching(IOUSBDevice)",
            evidence: [
              "device_name=\(name)",
              "device_class=Billboard",
              "data_endpoints=\(endpoints)",
            ]))
        }
      }

      // Check for known attack device names
      let deviceStr = "\(name) \(device["USB Vendor Name"] as? String ?? "")"
      for s in suspicious where deviceStr.localizedCaseInsensitiveContains(s) {
        result.append(.filesystem(
          name: s, path: "ioreg:IOUSB",
          technique: "Known Attack Device",
          description: "Known attack USB device detected: \(s)",
          severity: .critical, mitreID: "T1200",
          scannerId: "usb",
          enumMethod: "IOKit → IOServiceMatching(IOUSBDevice)",
          evidence: [
            "matched_name=\(s)",
            "device_string=\(deviceStr)",
          ]))
      }
    }
    return result
  }

  /// Check for recently mounted external volumes (potential USB attack)
  private func scanExternalVolumes() -> [ProcessAnomaly] {
    var result: [ProcessAnomaly] = []
    let fm = FileManager.default
    guard let mounts = try? fm.contentsOfDirectory(atPath: "/Volumes") else {
      return result
    }
    for mount in mounts where mount != "Macintosh HD" && mount != "Recovery" {
      let path = "/Volumes/\(mount)"
      let autorunNames = [
        ".autorun", "autorun.inf", ".DS_Store.lnk",
        "Thumbs.db.lnk", ".Trashes.command",
      ]
      for ar in autorunNames where fm.fileExists(atPath: "\(path)/\(ar)") {
        result.append(.filesystem(
          name: ar, path: "\(path)/\(ar)",
          technique: "USB Autorun Artifact",
          description: "Autorun file on external volume '\(mount)': \(ar)",
          severity: .high, mitreID: "T1091",
          scannerId: "usb",
          enumMethod: "FileManager.fileExists → /Volumes autorun check",
          evidence: [
            "volume=\(mount)",
            "autorun_file=\(ar)",
            "path=\(path)/\(ar)",
          ]))
      }
    }
    return result
  }
}
