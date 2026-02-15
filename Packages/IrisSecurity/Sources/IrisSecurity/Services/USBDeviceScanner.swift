import Foundation
import os.log

/// Scans for suspicious USB devices that may be implants.
/// USB implants masquerade as chargers but have data endpoints.
/// Covers hunt scripts: usb_devices.
public actor USBDeviceScanner {
    public static let shared = USBDeviceScanner()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "USBScanner")

    public func scan() async -> [ProcessAnomaly] {
        var anomalies: [ProcessAnomaly] = []
        anomalies.append(contentsOf: await scanUSBDevices())
        anomalies.append(contentsOf: await scanExternalVolumes())
        return anomalies
    }

    /// Parse ioreg for USB devices with suspicious characteristics
    private func scanUSBDevices() async -> [ProcessAnomaly] {
        guard let output = runCmd("/usr/sbin/ioreg", args: ["-p", "IOUSB", "-l", "-w0"]) else { return [] }
        var result: [ProcessAnomaly] = []

        let devices = output.components(separatedBy: "+-o ")
        for device in devices {
            // Billboard devices are USB-C accessories that claim charging-only
            // but have data endpoints — potential USB implants
            if device.contains("Billboard") {
                let name = device.split(separator: "\n").first.map(String.init) ?? "Billboard Device"
                // Check for data endpoints
                if device.contains("bNumEndpoints") {
                    let endpointLine = device.split(separator: "\n").first(where: { $0.contains("bNumEndpoints") })
                    let endpoints = endpointLine.flatMap { line -> Int? in
                        let parts = line.split(separator: "=")
                        return parts.last.flatMap { Int($0.trimmingCharacters(in: .whitespaces)) }
                    } ?? 0

                    if endpoints > 0 {
                        result.append(.filesystem(
                            name: String(name.prefix(60)), path: "ioreg:IOUSB",
                            technique: "USB Implant Suspect",
                            description: "Billboard USB device with \(endpoints) data endpoint(s). Claimed charging-only but has data capability.",
                            severity: .high, mitreID: "T1200"))
                    }
                }
            }

            // Check for devices with suspicious vendor strings
            let suspicious = ["BadUSB", "Rubber Ducky", "USB Armory", "LAN Turtle",
                             "Bash Bunny", "WiFi Pineapple", "O.MG Cable"]
            for s in suspicious where device.lowercased().contains(s.lowercased()) {
                result.append(.filesystem(
                    name: s, path: "ioreg:IOUSB",
                    technique: "Known Attack Device",
                    description: "Known attack USB device detected: \(s).",
                    severity: .critical, mitreID: "T1200"))
            }
        }
        return result
    }

    /// Check for recently mounted external volumes (potential USB attack)
    private func scanExternalVolumes() async -> [ProcessAnomaly] {
        var result: [ProcessAnomaly] = []
        let fm = FileManager.default
        let volumes = "/Volumes"
        guard let mounts = try? fm.contentsOfDirectory(atPath: volumes) else { return result }

        for mount in mounts where mount != "Macintosh HD" && mount != "Recovery" {
            let path = "\(volumes)/\(mount)"
            // Check for autorun-style files
            let autorunNames = [".autorun", "autorun.inf", ".DS_Store.lnk",
                                 "Thumbs.db.lnk", ".Trashes.command"]
            for ar in autorunNames {
                if fm.fileExists(atPath: "\(path)/\(ar)") {
                    result.append(.filesystem(
                        name: ar, path: "\(path)/\(ar)",
                        technique: "USB Autorun Artifact",
                        description: "Autorun-style file on external volume '\(mount)': \(ar)",
                        severity: .high, mitreID: "T1091"))
                }
            }
        }
        return result
    }

    private func runCmd(_ path: String, args: [String]) -> String? {
        let proc = Process(); proc.executableURL = URL(fileURLWithPath: path)
        proc.arguments = args
        let pipe = Pipe(); proc.standardOutput = pipe; proc.standardError = pipe
        try? proc.run(); proc.waitUntilExit()
        return String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8)
    }
}
