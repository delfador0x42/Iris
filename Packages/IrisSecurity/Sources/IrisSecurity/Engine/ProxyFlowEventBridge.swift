//
//  ProxyFlowEventBridge.swift
//  IrisSecurity
//
//  Bridges captured HTTP flows from ProxyStore into the unified Event pipeline.
//  Converts ProxyCapturedFlow objects to Events with Kind.httpFlow,
//  enabling C2, exfiltration, and data theft detection rules.
//

import Foundation
import os.log

actor ProxyFlowEventBridge {
  static let shared = ProxyFlowEventBridge()
  private let logger = Logger(subsystem: "com.wudan.iris", category: "ProxyBridge")

  private var seenIds: Set<UUID> = []
  private var isRunning = false
  private var pollTask: Task<Void, Never>?

  func start() {
    guard !isRunning else { return }
    isRunning = true
    pollTask = Task { await pollLoop() }
    logger.info("[PROXY-BRIDGE] Started")
  }

  func stop() {
    isRunning = false
    pollTask?.cancel()
    pollTask = nil
  }

  private func pollLoop() async {
    while isRunning && !Task.isCancelled {
      await pollFlows()
      try? await Task.sleep(nanoseconds: 2_000_000_000)
    }
  }

  private func pollFlows() async {
    let flows = await MainActor.run { ProxyStore.shared.flows }
    var newEvents: [Event] = []

    for flow in flows where flow.isHTTP {
      guard !seenIds.contains(flow.id) else { continue }
      seenIds.insert(flow.id)

      guard let request = flow.request else { continue }

      let method = request.method
      let host = flow.host
      let path = extractPath(from: request.url)
      let status = UInt16(flow.response?.statusCode ?? 0)
      let bytes = UInt64(flow.bytesIn + flow.bytesOut)

      var fields: [String: String] = [
        "method": method,
        "host": host,
        "url": request.url,
        "flow_type": flow.flowType.rawValue,
      ]
      if let processName = flow.processName {
        fields["process_name"] = processName
      }
      if status > 0 {
        fields["status_code"] = "\(status)"
      }
      if let contentType = flow.response?.contentType {
        fields["content_type"] = contentType
      }

      newEvents.append(Event(
        id: EventIDGen.shared.next(),
        source: .proxy,
        severity: .info,
        process: ProcessRef(
          pid: Int32(flow.processId ?? 0),
          path: "", sign: flow.processName ?? ""),
        kind: .httpFlow(
          method: method, host: host, path: path,
          status: status, bytes: bytes),
        fields: fields))
    }

    if !newEvents.isEmpty {
      await SecurityEventBus.shared.ingest(newEvents)
      if seenIds.count > 50_000 {
        seenIds = Set(flows.map(\.id))
      }
    }
  }

  private func extractPath(from url: String) -> String {
    // URL format: "https://host/path" — extract path after host
    if let range = url.range(of: "://") {
      let afterScheme = url[range.upperBound...]
      if let slashIdx = afterScheme.firstIndex(of: "/") {
        return String(afterScheme[slashIdx...])
      }
    }
    return "/"
  }
}
