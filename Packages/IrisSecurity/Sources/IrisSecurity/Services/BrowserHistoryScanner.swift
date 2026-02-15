import Foundation
import os.log

/// Analyzes browser history databases for C2 indicators.
/// Checks Safari, Chrome, Firefox, Brave for connections to known
/// malicious domains, dead drop resolvers, and cloud C2 patterns.
/// Covers: browser_history.sh hunt script.
public actor BrowserHistoryScanner {
  public static let shared = BrowserHistoryScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "BrowserHistory")

  /// Suspicious domain patterns from malware analysis
  private static let suspiciousDomains: [(pattern: String, desc: String)] = [
    ("pastebin.com/raw", "Pastebin raw — dead drop resolver"),
    ("raw.githubusercontent.com", "GitHub raw — dead drop/payload host"),
    ("api.telegram.org", "Telegram API — C2 channel"),
    ("steamcommunity.com/id/", "Steam Community — dead drop"),
    ("translate.google.com/translate", "Google Translate — redirect abuse"),
    (".onion", "Tor hidden service"),
    ("ngrok.io", "Ngrok tunnel — C2 relay"),
    ("serveo.net", "Serveo tunnel — C2 relay"),
  ]

  /// Browser history database paths
  private static let historyDBs: [(browser: String, path: String)] = [
    ("Safari", "Library/Safari/History.db"),
    ("Chrome", "Library/Application Support/Google/Chrome/Default/History"),
    ("Firefox", "Library/Application Support/Firefox/Profiles"),
    ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser/Default/History"),
    ("Edge", "Library/Application Support/Microsoft Edge/Default/History"),
  ]

  public func scan() async -> [ProcessAnomaly] {
    var anomalies: [ProcessAnomaly] = []
    let home = NSHomeDirectory()
    for (browser, relPath) in Self.historyDBs {
      let dbPath = "\(home)/\(relPath)"
      if browser == "Firefox" {
        anomalies.append(contentsOf: await scanFirefoxHistory(profileDir: dbPath))
      } else {
        anomalies.append(contentsOf: await scanChromiumHistory(browser: browser, dbPath: dbPath))
      }
    }
    return anomalies
  }

  /// Scan Chromium/Safari-style history database
  private func scanChromiumHistory(browser: String, dbPath: String) async -> [ProcessAnomaly] {
    guard FileManager.default.fileExists(atPath: dbPath) else { return [] }
    var anomalies: [ProcessAnomaly] = []
    // Safari uses history_items.url, Chromium uses urls.url
    let table = browser == "Safari" ? "history_items" : "urls"
    let column = browser == "Safari" ? "url" : "url"
    let query = "SELECT \(column) FROM \(table) ORDER BY rowid DESC LIMIT 5000;"
    let output = await runCommand("/usr/bin/sqlite3", args: [dbPath, query])
    for line in output.components(separatedBy: "\n") where !line.isEmpty {
      for (pattern, desc) in Self.suspiciousDomains where line.contains(pattern) {
        anomalies.append(.filesystem(
          name: browser, path: dbPath,
          technique: "Suspicious Browser History",
          description: "\(browser) visited \(desc): \(line.prefix(100))",
          severity: .medium, mitreID: "T1071.001"
        ))
      }
    }
    return anomalies
  }

  /// Scan Firefox history (profile directory)
  private func scanFirefoxHistory(profileDir: String) async -> [ProcessAnomaly] {
    let fm = FileManager.default
    guard let profiles = try? fm.contentsOfDirectory(atPath: profileDir) else { return [] }
    for profile in profiles where profile.hasSuffix(".default-release") || profile.hasSuffix(".default") {
      let dbPath = "\(profileDir)/\(profile)/places.sqlite"
      if fm.fileExists(atPath: dbPath) {
        return await scanChromiumHistory(browser: "Firefox", dbPath: dbPath)
      }
    }
    return []
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
