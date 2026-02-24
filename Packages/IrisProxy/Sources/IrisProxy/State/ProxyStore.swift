//
//  ProxyStore.swift
//  IrisProxy
//
//  Main state store for proxy functionality.
//  Manages connection to proxy extension and captured flows (HTTP, TCP, UDP).
//

import Foundation
import SwiftUI
import os.log

/// Main store for HTTP proxy state and captured flows.
@MainActor @Observable
public final class ProxyStore {

  // MARK: - State

  /// Whether the proxy extension is enabled.
  public internal(set) var isEnabled: Bool = false

  /// Whether TLS interception is enabled.
  public internal(set) var isInterceptionEnabled: Bool = true

  /// All captured HTTP flows.
  public internal(set) var flows: [ProxyCapturedFlow] = []

  /// Currently selected flow for detail view.
  public var selectedFlow: ProxyCapturedFlow?

  /// Current search/filter query.
  public var searchQuery: String = ""

  /// Active method filter (nil = all methods).
  public var methodFilter: String?

  /// Active status code filter (nil = all statuses).
  public var statusFilter: StatusFilter = .all

  /// Active protocol filter (nil = all protocols).
  public var protocolFilter: ProxyFlowType?

  /// Whether currently loading flows.
  public internal(set) var isLoading: Bool = false

  /// Connection error message.
  public internal(set) var errorMessage: String?

  /// Total number of captured flows (including filtered out).
  public internal(set) var totalFlowCount: Int = 0

  // MARK: - Properties

  let logger = Logger(subsystem: "com.wudan.iris", category: "ProxyStore")
  var xpcConnection: NSXPCConnection?
  var refreshTimer: Timer?
  private var searchTask: Task<Void, Never>?

  /// Last seen sequence number from the proxy extension.
  /// Used for delta XPC protocol — only fetch flows newer than this.
  var lastSeenSequence: UInt64 = 0

  // MARK: - Singleton

  /// Shared instance for app-wide use.
  public static let shared = ProxyStore()

  // MARK: - Initialization

  public init() {}

  // Singleton — never deallocated, no deinit needed
}

// MARK: - Status Filter

/// Filter for HTTP status codes.
public enum StatusFilter: String, CaseIterable, Identifiable {
  case all = "All"
  case success = "2xx"
  case redirect = "3xx"
  case clientError = "4xx"
  case serverError = "5xx"
  case pending = "Pending"
  case error = "Error"

  public var id: String { rawValue }
}

// MARK: - Flow Statistics

/// Statistics about captured flows.
public struct FlowStatistics {
  public let total: Int
  public let successful: Int
  public let failed: Int
  public let pending: Int
  public let errors: Int
  public let totalBytes: Int
  public let averageDuration: TimeInterval

  public var totalBytesFormatted: String {
    ByteCountFormatter.string(fromByteCount: Int64(totalBytes), countStyle: .file)
  }

  public var averageDurationFormatted: String {
    if averageDuration < 1 {
      return String(format: "%.0fms", averageDuration * 1000)
    } else {
      return String(format: "%.2fs", averageDuration)
    }
  }
}

// MARK: - XPC Types
// ProxyCapturedFlow, ProxyCapturedRequest, ProxyCapturedResponse, and ProxyXPCInterface
// are defined in IrisShared/Protocols/ProxyXPCProtocol.swift
