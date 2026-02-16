import Foundation
import os.log

/// Analyzes browser history databases for C2 indicators.
/// Checks Safari, Chrome, Firefox, Brave for connections to known
/// malicious domains, dead drop resolvers, and cloud C2 patterns.
/// Uses SQLiteReader — no shell-outs.
public actor BrowserHistoryScanner {
  public static let shared = BrowserHistoryScanner()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "BrowserHistory")

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
        anomalies.append(contentsOf: scanFirefoxHistory(profileDir: dbPath))
      } else {
        anomalies.append(contentsOf: scanHistory(browser: browser, dbPath: dbPath))
      }
    }
    return anomalies
  }

  /// Scan Chromium/Safari-style history database via SQLiteReader
  private func scanHistory(browser: String, dbPath: String) -> [ProcessAnomaly] {
    guard let db = SQLiteReader(path: dbPath) else { return [] }
    let table = browser == "Safari" ? "history_items" : "urls"
    let rows = db.query("SELECT url FROM \(table) ORDER BY rowid DESC LIMIT 5000;")
    var anomalies: [ProcessAnomaly] = []
    for row in rows {
      guard let url = row.first ?? nil, !url.isEmpty else { continue }
      for (pattern, desc) in Self.suspiciousDomains where url.contains(pattern) {
        anomalies.append(.filesystem(
          name: browser, path: dbPath,
          technique: "Suspicious Browser History",
          description: "\(browser) visited \(desc): \(url.prefix(100))",
          severity: .medium, mitreID: "T1071.001"))
      }
    }
    return anomalies
  }

  /// Scan Firefox history (profile directory structure)
  private func scanFirefoxHistory(profileDir: String) -> [ProcessAnomaly] {
    let fm = FileManager.default
    guard let profiles = try? fm.contentsOfDirectory(atPath: profileDir) else {
      return []
    }
    for profile in profiles
    where profile.hasSuffix(".default-release") || profile.hasSuffix(".default") {
      let dbPath = "\(profileDir)/\(profile)/places.sqlite"
      if fm.fileExists(atPath: dbPath) {
        return scanHistory(browser: "Firefox", dbPath: dbPath)
      }
    }
    return []
  }
}
