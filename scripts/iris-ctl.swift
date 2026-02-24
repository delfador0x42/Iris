#!/usr/bin/env swift
//
//  iris-ctl.swift — CLI controller for the Iris EDR
//
//  Connects to running Iris app via Unix domain socket at /tmp/iris.sock.
//  Sends JSON command, receives streaming JSONL responses.
//
//  Commands:
//    iris-ctl status              System state
//    iris-ctl dump                Full system dump (everything the GUI sees)
//    iris-ctl scan                Full threat scan (streams progress)
//    iris-ctl tail                Stream all events (Ctrl+C to stop)
//    iris-ctl tail --kind=alert   Stream only alerts
//    iris-ctl tail --severity=high Stream high+ severity
//    iris-ctl alerts [n]          Recent alerts (default 100)
//    iris-ctl findings [n]        Recent scan findings (default 500)
//    iris-ctl stats               Detection engine statistics
//    iris-ctl probe               Run all contradiction probes
//    iris-ctl query --kind=exec --since=300  Query events
//    iris-ctl snapshot            Current system state
//    iris-ctl watch               Tail JSONL file directly (no app needed)
//

import Foundation

let socketPath = "/tmp/iris.sock"
let args = CommandLine.arguments
let action = args.count > 1 ? args[1] : "status"

// Commands that don't need the socket
if action == "watch" {
    watchEventStream()
    exit(0)
}
if action == "help" || action == "--help" || action == "-h" {
    printHelp()
    exit(0)
}

// Parse flags from remaining args
var flags: [String: String] = [:]
for arg in args.dropFirst(2) {
    if arg.hasPrefix("--") {
        let parts = arg.dropFirst(2).split(separator: "=", maxSplits: 1)
        if parts.count == 2 {
            flags[String(parts[0])] = String(parts[1])
        } else {
            flags[String(parts[0])] = "true"
        }
    } else {
        // Positional arg — treat as limit
        flags["limit"] = arg
    }
}

// Build JSON command
var cmd: [String: Any] = ["action": action]
for (k, v) in flags {
    if let n = Int(v) { cmd[k] = n }
    else { cmd[k] = v }
}

// Connect to socket
let fd = socket(AF_UNIX, SOCK_STREAM, 0)
guard fd >= 0 else {
    printErr("socket() failed: \(errno)")
    exit(1)
}

var addr = sockaddr_un()
addr.sun_family = sa_family_t(AF_UNIX)
withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
    let buf = UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self)
    socketPath.withCString { src in _ = strcpy(buf, src) }
}

let addrLen = socklen_t(MemoryLayout<sockaddr_un>.size)
let connectResult = withUnsafePointer(to: &addr) { ptr in
    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, addrLen) }
}
guard connectResult == 0 else {
    printErr("Cannot connect to \(socketPath) — is Iris running?")
    close(fd)
    exit(1)
}

// Send command as JSON line
guard let jsonData = try? JSONSerialization.data(withJSONObject: cmd),
      let jsonStr = String(data: jsonData, encoding: .utf8) else {
    printErr("Failed to serialize command")
    close(fd)
    exit(1)
}
let lineData = (jsonStr + "\n").utf8
_ = lineData.withContiguousStorageIfAvailable { buf in
    write(fd, buf.baseAddress!, buf.count)
}

// Read streaming JSONL response
let isStreaming = action == "tail"
let isScan = action == "scan"

// Install signal handler for clean exit on Ctrl+C
signal(SIGINT) { _ in exit(0) }
signal(SIGPIPE, SIG_IGN)

var buf = [UInt8](repeating: 0, count: 8192)
var lineBuf = ""

while true {
    let n = read(fd, &buf, buf.count)
    guard n > 0 else { break }

    lineBuf += String(bytes: buf[..<n], encoding: .utf8) ?? ""

    // Process complete lines
    while let nlRange = lineBuf.range(of: "\n") {
        let line = String(lineBuf[..<nlRange.lowerBound])
        lineBuf = String(lineBuf[nlRange.upperBound...])

        if line.isEmpty { continue }

        if isScan {
            formatScanLine(line)
        } else if isStreaming || action == "alerts" || action == "findings" {
            formatEventLine(line)
        } else {
            // One-shot: pretty-print JSON
            prettyPrint(line)
        }
    }
}

close(fd)

// MARK: - Formatters

func formatEventLine(_ line: String) {
    guard let data = line.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        print(line.prefix(200))
        return
    }

    let severity = obj["severity"] as? String ?? ""
    let kind = (obj["kind"] as? [String: Any])?.keys.first ?? "?"
    let proc = obj["process"] as? [String: Any]
    let path = proc?["path"] as? String ?? ""
    let pid = proc?["pid"] as? Int ?? 0
    let name = (path as NSString).lastPathComponent

    let sevIcon: String
    switch severity.lowercased() {
    case "critical": sevIcon = "!!"
    case "high": sevIcon = "! "
    case "medium": sevIcon = "* "
    case "low": sevIcon = "- "
    default: sevIcon = "  "
    }

    // For alerts, show more detail
    if kind == "alert" {
        if let alertData = (obj["kind"] as? [String: Any])?["alert"] as? [String: Any] {
            let ruleName = alertData["name"] as? String ?? ""
            let mitre = alertData["mitre"] as? String ?? ""
            print("\(sevIcon)[\(severity.uppercased().padding(toLength: 8, withPad: " ", startingAt: 0))] \(ruleName) — \(name) (pid \(pid)) \(mitre)")
            return
        }
    }

    // For scan findings
    if kind == "scanFinding" {
        if let findData = (obj["kind"] as? [String: Any])?["scanFinding"] as? [String: Any] {
            let technique = findData["technique"] as? String ?? ""
            let mitre = findData["mitre"] as? String ?? ""
            print("\(sevIcon)[\(severity.uppercased().padding(toLength: 8, withPad: " ", startingAt: 0))] \(technique) — \(name) \(mitre)")
            return
        }
    }

    // For probe results
    if kind == "probeResult" {
        if let probeData = (obj["kind"] as? [String: Any])?["probeResult"] as? [String: Any] {
            let probeId = probeData["probeId"] as? String ?? ""
            let verdict = probeData["verdict"] as? String ?? ""
            let icon = verdict == "contradiction" ? "!!" : "OK"
            print("  [\(icon)] PROBE \(probeId): \(verdict)")
            return
        }
    }

    // Generic event
    print("\(sevIcon)\(kind.padding(toLength: 12, withPad: " ", startingAt: 0)) pid=\(pid) \(name)")
}

func formatScanLine(_ line: String) {
    guard let data = line.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        print(line.prefix(200))
        return
    }

    let type = obj["type"] as? String ?? ""
    if type == "progress" {
        let completed = obj["completed"] as? Int ?? 0
        let total = obj["total"] as? Int ?? 0
        let scanner = obj["scanner"] as? String ?? ""
        let findings = obj["findings"] as? Int ?? 0
        printErr("  [\(completed)/\(total)] \(scanner) — \(findings) findings")
    } else if type == "scanComplete" {
        let total = obj["totalFindings"] as? Int ?? 0
        let critical = obj["criticalCount"] as? Int ?? 0
        let high = obj["highCount"] as? Int ?? 0
        let ms = obj["durationMs"] as? Int ?? 0
        let scanners = obj["scannerCount"] as? Int ?? 0
        let correlations = obj["correlations"] as? Int ?? 0
        let campaigns = obj["campaigns"] as? Int ?? 0
        print("\n═══ SCAN COMPLETE ═══")
        print("Duration:     \(ms)ms (\(scanners) scanners)")
        print("Findings:     \(total) total (\(critical) critical, \(high) high)")
        print("Correlations: \(correlations)")
        print("Campaigns:    \(campaigns)")
    } else {
        prettyPrint(line)
    }
}

func prettyPrint(_ line: String) {
    guard let data = line.data(using: .utf8),
          let obj = try? JSONSerialization.jsonObject(with: data, options: []),
          let pretty = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
          let str = String(data: pretty, encoding: .utf8) else {
        print(line)
        return
    }
    print(str)
}

// MARK: - Watch (tail JSONL file directly, no app needed)

func watchEventStream() {
    let home = FileManager.default.homeDirectoryForCurrentUser
    let path = home.appendingPathComponent(".iris/events.jsonl").path

    guard FileManager.default.fileExists(atPath: path) else {
        printErr("Event stream not found: \(path)")
        printErr("Start Iris app to begin logging events.")
        exit(1)
    }

    printErr("═══ IRIS EVENT STREAM (\(path)) ═══")
    printErr("Press Ctrl+C to stop\n")

    guard let fh = FileHandle(forReadingAtPath: path) else {
        printErr("Cannot open: \(path)")
        exit(1)
    }
    // Seek to last 4KB for recent context
    let size = fh.seekToEndOfFile()
    if size > 4096 { fh.seek(toFileOffset: size - 4096) }
    else { fh.seek(toFileOffset: 0) }
    let initial = fh.readDataToEndOfFile()
    if let text = String(data: initial, encoding: .utf8) {
        let lines = text.components(separatedBy: "\n").filter { !$0.isEmpty }
        let start = size > 4096 ? 1 : 0
        for line in lines.dropFirst(start) {
            formatEventLine(line)
        }
    }

    signal(SIGINT) { _ in exit(0) }
    while true {
        let newData = fh.availableData
        if !newData.isEmpty, let text = String(data: newData, encoding: .utf8) {
            for line in text.components(separatedBy: "\n") where !line.isEmpty {
                formatEventLine(line)
            }
        }
        Thread.sleep(forTimeInterval: 0.25)
    }
}

func printHelp() {
    print("""
    iris-ctl — CLI controller for the Iris EDR

    COMMANDS (via Unix socket, requires running Iris app):
      status              System state (event bus, stream, threat engine)
      dump                Full system dump (processes, network, DNS, alerts, probes)
      scan                Full threat scan (streams progress + findings)
      tail                Stream all events in real-time (Ctrl+C to stop)
      tail --kind=alert   Stream only alerts
      tail --severity=high  Stream high+ severity events
      alerts [n]          Recent alerts (default 100)
      findings [n]        Recent scan findings (default 500)
      stats               Detection engine statistics
      probe               Run all contradiction probes
      query               Query events (--kind, --severity, --since, --limit)
      snapshot            Current system state

    COMMANDS (no app required):
      watch               Tail JSONL file directly (Ctrl+C to stop)
      help                Show this help

    EXAMPLES:
      iris-ctl tail --kind=alert --severity=critical
      iris-ctl query --kind=exec --since=300 --limit=50
      iris-ctl alerts 20
      iris-ctl scan
    """)
}

func printErr(_ msg: String) {
    FileHandle.standardError.write(Data((msg + "\n").utf8))
}
