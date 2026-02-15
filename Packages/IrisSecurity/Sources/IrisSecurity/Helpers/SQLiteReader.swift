import Foundation
import SQLite3

/// Native SQLite3 reader — replaces shell-outs to /usr/bin/sqlite3.
/// Used by TCC, browser history, kext policy, and screen capture scanners.
public final class SQLiteReader {
  private var db: OpaquePointer?

  /// Open a database at path. Returns nil if open fails.
  public init?(path: String) {
    guard sqlite3_open_v2(
      path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nil
    ) == SQLITE_OK else {
      sqlite3_close(db)
      return nil
    }
  }

  deinit { sqlite3_close(db) }

  /// Execute a query and return rows as arrays of optional strings.
  public func query(_ sql: String) -> [[String?]] {
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
          let stmt else { return [] }
    defer { sqlite3_finalize(stmt) }

    let colCount = sqlite3_column_count(stmt)
    var rows: [[String?]] = []
    while sqlite3_step(stmt) == SQLITE_ROW {
      var row: [String?] = []
      row.reserveCapacity(Int(colCount))
      for i in 0..<colCount {
        if let text = sqlite3_column_text(stmt, i) {
          row.append(String(cString: text))
        } else {
          row.append(nil)
        }
      }
      rows.append(row)
    }
    return rows
  }

  /// Execute a query and return rows as dictionaries.
  public func queryDicts(_ sql: String) -> [[String: String]] {
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK,
          let stmt else { return [] }
    defer { sqlite3_finalize(stmt) }

    let colCount = sqlite3_column_count(stmt)
    let colNames = (0..<colCount).map {
      String(cString: sqlite3_column_name(stmt, $0))
    }

    var rows: [[String: String]] = []
    while sqlite3_step(stmt) == SQLITE_ROW {
      var row: [String: String] = [:]
      for i in 0..<colCount {
        if let text = sqlite3_column_text(stmt, i) {
          row[colNames[Int(i)]] = String(cString: text)
        }
      }
      rows.append(row)
    }
    return rows
  }
}
