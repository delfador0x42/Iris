#!/usr/bin/env swift
//
//  iris-ctl.swift — CLI controller for the Iris EDR
//
//  Sends commands to the running Iris app via DistributedNotificationCenter.
//  All scan results, alerts, probes, and stats are written to /tmp/iris-*.json.
//
//  Commands:
//    iris-ctl status          System state (extensions, proxy, detection stats)
//    iris-ctl scan            Full threat scan with all findings
//    iris-ctl alerts          Recent detection alerts
//    iris-ctl stats           Detection engine statistics
//    iris-ctl export          Comprehensive export (everything in one file)
//    iris-ctl snapshot        Latest system snapshot
//    iris-ctl probe           Run all contradiction probes
//    iris-ctl probeOne <id>   Run a single probe
//    iris-ctl probeStatus     Read cached probe results
//    iris-ctl reinstall       Clean reinstall all extensions
//    iris-ctl startProxy      Enable transparent proxy
//    iris-ctl stopProxy       Disable transparent proxy
//    iris-ctl sendCA          Resend CA cert to proxy
//    iris-ctl checkExtensions Check extension statuses
//    iris-ctl dump            Full state dump (processes, network, DNS, alerts, probes)
//    iris-ctl watch           Tail real-time event stream (no app needed)
//    iris-ctl tail [n]        Read last N lines from alerts log
//    iris-ctl read <file>     Read a diagnostic file directly
//

import Foundation

let commandName = Notification.Name("com.wudan.iris.command")
let responseName = Notification.Name("com.wudan.iris.response")

let args = CommandLine.arguments
let action = args.count > 1 ? args[1] : "status"

// Commands that don't need the app running
if action == "tail" {
  let n = args.count > 2 ? Int(args[2]) ?? 20 : 20
  tailAlerts(n)
  exit(0)
}

if action == "watch" {
  watchEventStream()
  exit(0)
}

if action == "read" {
  guard args.count > 2 else {
    printErr("Usage: iris-ctl read <path>")
    printErr("Paths: /tmp/iris-status.json, /tmp/iris-scan-results.json, etc.")
    exit(1)
  }
  readFile(args[2])
  exit(0)
}

if action == "help" {
  printHelp()
  exit(0)
}

let validCommands = [
  "status", "reinstall", "startProxy", "stopProxy", "sendCA", "checkExtensions",
  "cleanProxy", "installNetwork", "scan", "alerts", "stats", "export", "snapshot",
  "probe", "probeOne", "probeStatus", "dump", "watch",
]
guard validCommands.contains(action) else {
  printErr("Unknown command: \(action)")
  printHelp()
  exit(1)
}

// Delete stale output before requesting
let outputFiles: [String: String] = [
  "status": "/tmp/iris-status.json",
  "checkExtensions": "/tmp/iris-status.json",
  "scan": "/tmp/iris-scan-results.json",
  "alerts": "/tmp/iris-alerts.json",
  "stats": "/tmp/iris-stats.json",
  "export": "/tmp/iris-export.json",
  "snapshot": "/tmp/iris-snapshot.json",
  "probe": "/tmp/iris-probes.json",
  "probeStatus": "/tmp/iris-probes.json",
  "dump": "/tmp/iris-dump.json",
]
if let path = outputFiles[action] {
  try? FileManager.default.removeItem(atPath: path)
}

// Listen for response
var gotResponse = false
let center = DistributedNotificationCenter.default()
let observer = center.addObserver(forName: responseName, object: nil, queue: .main) { n in
  if let status = n.userInfo?["status"] as? String,
     let respAction = n.userInfo?["action"] as? String,
     respAction == action
  {
    if status != "ok" { printErr("[\(action)] \(status)") }
    gotResponse = true
  }
}

// Build userInfo
var userInfo: [String: String] = ["action": action]
if action == "probeOne" {
  guard args.count > 2 else {
    printErr("Usage: iris-ctl probeOne <probe-id>")
    printErr("IDs: dyld-cache, sip-status, process-census, binary-integrity, network-ghost,")
    printErr("     kext-census, dns-contradiction, timing-oracle, trust-cache")
    exit(1)
  }
  userInfo["probeId"] = args[2]
}

// Send command
let isLong = ["scan", "probe", "export", "dump"].contains(action)
printErr("→ \(action)\(isLong ? " (this may take a moment...)" : "")")
center.postNotificationName(commandName, object: nil, userInfo: userInfo, deliverImmediately: true)

// Wait
let timeout: TimeInterval = isLong ? 120 : 15
let deadline = Date().addingTimeInterval(timeout)
while !gotResponse && Date() < deadline {
  RunLoop.main.run(until: Date().addingTimeInterval(0.1))
}
center.removeObserver(observer)

if !gotResponse {
  printErr("No response from Iris app (is it running?)")
  exit(1)
}

// Read and display result
Thread.sleep(forTimeInterval: 0.3) // wait for file write
let resultPath: String? = {
  if action == "probeOne", args.count > 2 {
    return "/tmp/iris-probe-\(args[2]).json"
  }
  return outputFiles[action]
}()

if let path = resultPath {
  if let data = FileManager.default.contents(atPath: path),
     let json = String(data: data, encoding: .utf8)
  {
    // For scan results, print a summary header
    if action == "scan" { printScanSummary(data) }
    else if action == "alerts" { printAlertsSummary(data) }
    else if action == "stats" { printStatsSummary(data) }
    else if action == "probe" || action == "probeStatus" { printProbeSummary(data) }
    else if action == "dump" { printDumpSummary(data) }
    else { print(json) }
  } else {
    printErr("Output file not found: \(path)")
  }
}

// MARK: - Output Formatters

func printScanSummary(_ data: Data) {
  guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    print(String(data: data, encoding: .utf8) ?? "")
    return
  }
  let total = obj["totalFindings"] as? Int ?? 0
  let critical = obj["criticalCount"] as? Int ?? 0
  let high = obj["highCount"] as? Int ?? 0
  let duration = obj["totalDurationMs"] as? Int ?? 0
  let scanners = obj["scannerCount"] as? Int ?? 0
  let correlations = obj["correlationCount"] as? Int ?? 0
  let campaigns = obj["campaignCount"] as? Int ?? 0

  print("═══ IRIS SCAN RESULTS ═══")
  print("Duration:     \(duration)ms (\(scanners) scanners)")
  print("Findings:     \(total) total (\(critical) critical, \(high) high)")
  print("Correlations: \(correlations)")
  print("Campaigns:    \(campaigns)")
  print("")

  if let findings = obj["findings"] as? [[String: Any]], !findings.isEmpty {
    print("─── FINDINGS ───")
    for f in findings.prefix(50) {
      let sev = f["severity"] as? String ?? "?"
      let tech = f["technique"] as? String ?? "?"
      let proc = f["processName"] as? String ?? "?"
      let desc = f["description"] as? String ?? ""
      let mitre = f["mitreID"] as? String ?? ""
      let icon = sev == "critical" ? "!!" : sev == "high" ? "! " : "  "
      print("\(icon)[\(sev.uppercased().padding(toLength: 8, withPad: " ", startingAt: 0))] \(tech)")
      print("   Process: \(proc)  \(mitre.isEmpty ? "" : "[\(mitre)]")")
      if !desc.isEmpty { print("   \(desc)") }
    }
    if findings.count > 50 { print("   ... and \(findings.count - 50) more") }
  }

  if let timings = obj["scannerTimings"] as? [[String: Any]], !timings.isEmpty {
    print("\n─── SCANNER TIMINGS ───")
    for t in timings.prefix(20) {
      let name = t["name"] as? String ?? t["id"] as? String ?? "?"
      let ms = t["durationMs"] as? Int ?? 0
      let count = t["findings"] as? Int ?? 0
      print("  \(String(ms).padding(toLength: 6, withPad: " ", startingAt: 0))ms  \(name) (\(count) findings)")
    }
  }
}

func printAlertsSummary(_ data: Data) {
  guard let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
    print(String(data: data, encoding: .utf8) ?? "")
    return
  }
  print("═══ IRIS ALERTS (\(arr.count)) ═══")
  for a in arr.prefix(50) {
    let sev = a["severity"] as? String ?? "?"
    let name = a["name"] as? String ?? "?"
    let proc = a["processName"] as? String ?? "?"
    let ts = a["timestamp"] as? String ?? ""
    let icon = sev == "critical" ? "!!" : sev == "high" ? "! " : "  "
    print("\(icon)[\(sev.uppercased().padding(toLength: 8, withPad: " ", startingAt: 0))] \(name) — \(proc) (\(ts))")
  }
  if arr.count > 50 { print("   ... and \(arr.count - 50) more") }
}

func printStatsSummary(_ data: Data) {
  guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    print(String(data: data, encoding: .utf8) ?? "")
    return
  }
  print("═══ IRIS DETECTION STATS ═══")
  if let det = obj["detection"] as? [String: Any] {
    print("Events processed: \(det["eventsProcessed"] ?? 0)")
    print("Alerts produced:  \(det["alertsProduced"] ?? 0)")
    print("Rules loaded:     \(det["rulesLoaded"] ?? 0) simple + \(det["correlationRules"] ?? 0) correlation")
  }
  if let bus = obj["eventBus"] as? [String: Any] {
    print("Event bus:        \(bus["running"] as? Bool == true ? "RUNNING" : "STOPPED")")
    print("Total ingested:   \(bus["totalIngested"] ?? 0)")
  }
  if let alerts = obj["alertStore"] as? [String: Any] {
    print("Alert store:      \(alerts["critical"] ?? 0) critical, \(alerts["high"] ?? 0) high, \(alerts["medium"] ?? 0) medium, \(alerts["low"] ?? 0) low")
  }
}

func printProbeSummary(_ data: Data) {
  guard let arr = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
    print(String(data: data, encoding: .utf8) ?? "")
    return
  }
  let contradictions = arr.filter { ($0["verdict"] as? String) == "contradiction" }.count
  print("═══ IRIS PROBES (\(arr.count) run, \(contradictions) contradictions) ═══")
  for p in arr {
    let name = p["name"] as? String ?? p["id"] as? String ?? "?"
    let verdict = p["verdict"] as? String ?? "?"
    let icon = verdict == "contradiction" ? "!!" : "OK"
    print("  [\(icon)] \(name): \(verdict)")
    if let contras = p["contradictions"] as? [[String: Any]] {
      for c in contras {
        let label = c["label"] as? String ?? ""
        let v1 = c["value1"] as? String ?? ""
        let v2 = c["value2"] as? String ?? ""
        print("       \(label): \(v1) vs \(v2)")
      }
    }
  }
}

func printDumpSummary(_ data: Data) {
  guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    print(String(data: data, encoding: .utf8) ?? "")
    return
  }
  let procs = (obj["processes"] as? [Any])?.count ?? obj["processCount"] as? Int ?? 0
  let suspicious = obj["suspiciousCount"] as? Int ?? 0
  let conns = obj["connectionCount"] as? Int ?? 0
  let dnsCount = obj["dnsQueryCount"] as? Int ?? 0
  let flows = obj["proxyFlowCount"] as? Int ?? 0
  let alerts = (obj["alerts"] as? [Any])?.count ?? 0
  let probes = (obj["probes"] as? [Any])?.count ?? 0

  print("═══ IRIS FULL STATE DUMP ═══")
  print("Processes:    \(procs) live (\(suspicious) suspicious)")
  print("Network:      \(conns) connections")
  print("DNS:          \(dnsCount) queries")
  print("Proxy:        \(flows) flows")
  print("Alerts:       \(alerts)")
  print("Probes:       \(probes)")
  if let det = obj["detection"] as? [String: Any] {
    print("Detection:    \(det["eventsProcessed"] ?? 0) events, \(det["alertsProduced"] ?? 0) alerts")
  }
  if let path = obj["eventStreamPath"] as? String {
    print("Event stream: \(path)")
  }
  print("\nFull dump: /tmp/iris-dump.json")
}

// MARK: - Watch (tail event stream, no app needed)

func watchEventStream() {
  let home = FileManager.default.homeDirectoryForCurrentUser
  let path = home.appendingPathComponent("Library/Logs/Iris/events.jsonl").path

  guard FileManager.default.fileExists(atPath: path) else {
    printErr("Event stream not found: \(path)")
    printErr("Start Iris app to begin logging events.")
    exit(1)
  }

  printErr("═══ IRIS EVENT STREAM (\(path)) ═══")
  printErr("Press Ctrl+C to stop\n")

  // Read existing lines then follow
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
    // Skip first partial line if we seeked mid-file
    let start = size > 4096 ? 1 : 0
    for line in lines.dropFirst(start) {
      formatEventLine(line)
    }
  }

  // Poll for new data
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

func formatEventLine(_ line: String) {
  guard let data = line.data(using: .utf8),
        let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
    print(line.prefix(200))
    return
  }
  let type = obj["type"] as? String ?? "?"
  let ts = (obj["ts"] as? String ?? "").suffix(19)  // trim to readable length
  let proc = obj["process"] as? String ?? ""

  switch type {
  case "event":
    let evType = obj["eventType"] as? String ?? ""
    let source = obj["source"] as? String ?? ""
    let pid = obj["pid"] as? Int ?? 0
    print("  \(ts) [\(source)] \(evType) pid=\(pid) \(proc)")
  case "alert":
    let sev = obj["severity"] as? String ?? "?"
    let name = obj["name"] as? String ?? ""
    print("! \(ts) [\(sev.uppercased())] \(name) — \(proc)")
  case "probe":
    let name = obj["name"] as? String ?? ""
    let verdict = obj["verdict"] as? String ?? ""
    print("? \(ts) [PROBE] \(name): \(verdict)")
  default:
    print("  \(ts) [\(type)] \(proc)")
  }
}

// MARK: - Tail (read alert log directly, no app needed)

func tailAlerts(_ n: Int) {
  let home = FileManager.default.homeDirectoryForCurrentUser
  let alertPath = home.appendingPathComponent("Library/Application Support/Iris/alerts.jsonl").path
  let diagPath = home.appendingPathComponent("Library/Application Support/Iris/diagnostics.jsonl").path

  // Try alerts file first, then diagnostics
  let path = FileManager.default.fileExists(atPath: alertPath) ? alertPath : diagPath
  guard let data = FileManager.default.contents(atPath: path),
        let text = String(data: data, encoding: .utf8) else {
    printErr("No log file found at \(alertPath)")
    return
  }

  let lines = text.components(separatedBy: "\n").filter { !$0.isEmpty }
  let tail = Array(lines.suffix(n))
  print("═══ IRIS LOG (last \(tail.count) entries from \(path)) ═══")
  for line in tail {
    if let data = line.data(using: .utf8),
       let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
      let type = obj["type"] as? String ?? "?"
      let ts = obj["timestamp"] as? String ?? ""
      if type == "alert", let alert = obj["alert"] as? [String: Any] {
        let sev = alert["severity"] as? String ?? "?"
        let name = alert["name"] as? String ?? "?"
        let proc = alert["processName"] as? String ?? "?"
        print("  [\(sev.uppercased())] \(name) — \(proc) (\(ts))")
      } else if type == "scanComplete" {
        let count = (obj["anomalies"] as? [Any])?.count ?? 0
        print("  [SCAN] \(count) findings (\(ts))")
      } else if type == "integrityProbe" {
        let probe = (obj["integrityResults"] as? [String: Any])?["probe"] as? String ?? "?"
        let count = (obj["integrityResults"] as? [String: Any])?["findingCount"] as? Int ?? 0
        print("  [PROBE] \(probe): \(count) findings (\(ts))")
      }
    } else {
      print("  \(line.prefix(200))")
    }
  }
}

func readFile(_ path: String) {
  if let data = FileManager.default.contents(atPath: path),
     let text = String(data: data, encoding: .utf8) {
    print(text)
  } else {
    printErr("Cannot read: \(path)")
  }
}

func printHelp() {
  print("""
  iris-ctl — CLI controller for the Iris EDR

  COMMANDS (require running Iris app):
    status          System state (extensions, proxy, detection stats)
    scan            Full threat scan with all findings
    alerts          Recent detection alerts (from AlertStore)
    stats           Detection engine statistics
    export          Comprehensive export (scan + alerts + probes + stats)
    dump            Full state dump (processes, network, DNS, alerts, probes)
    snapshot        Latest system snapshot
    probe           Run all contradiction probes
    probeOne <id>   Run a single probe by ID
    probeStatus     Read cached probe results
    reinstall       Clean reinstall all extensions
    startProxy      Enable transparent proxy
    stopProxy       Disable transparent proxy
    sendCA          Resend CA cert to proxy extension
    checkExtensions Check extension statuses

  COMMANDS (no app required):
    watch           Tail real-time event stream (Ctrl+C to stop)
    tail [n]        Read last N entries from alert/diagnostic log
    read <path>     Read any diagnostic file directly
    help            Show this help

  OUTPUT FILES:
    /tmp/iris-dump.json           Full state dump (all stores)
    /tmp/iris-status.json         System state
    /tmp/iris-scan-results.json   Full scan results with findings
    /tmp/iris-alerts.json         Recent alerts
    /tmp/iris-stats.json          Detection engine stats
    /tmp/iris-export.json         Comprehensive export
    /tmp/iris-snapshot.json       Latest snapshot
    /tmp/iris-probes.json         Probe results

  EVENT STREAM:
    ~/Library/Logs/Iris/events.jsonl    Real-time JSONL (tail -f or iris-ctl watch)

  DIAGNOSTIC LOG:
    ~/Library/Application Support/Iris/diagnostics.jsonl
    ~/Library/Application Support/Iris/alerts.jsonl
    ~/Library/Application Support/Iris/latest-snapshot.json
    ~/Library/Application Support/Iris/latest-export.json
  """)
}

func printErr(_ msg: String) {
  FileHandle.standardError.write(Data((msg + "\n").utf8))
}
