import Combine
import Foundation

// MARK: - Filtering, Statistics & Search

@MainActor
extension ProxyStore {

  // MARK: - Search Debounce

  func setupSearchDebounce() {
    $searchQuery
      .debounce(for: .milliseconds(300), scheduler: RunLoop.main)
      .sink { [weak self] _ in
        self?.objectWillChange.send()
      }
      .store(in: &cancellables)
  }

  // MARK: - Filtered Flows

  /// Flows filtered by current search query, protocol, method, and status filters.
  public var filteredFlows: [ProxyCapturedFlow] {
    var result = flows

    // Apply protocol filter
    if let proto = protocolFilter {
      result = result.filter { $0.flowType == proto }
    }

    // Apply search query
    if !searchQuery.isEmpty {
      let query = searchQuery.lowercased()
      result = result.filter { flow in
        // Search host:port for all flows
        if flow.host.lowercased().contains(query) { return true }
        if String(flow.port).contains(query) { return true }
        if flow.processName?.lowercased().contains(query) ?? false { return true }
        // HTTP-specific: search URL and method
        if let request = flow.request {
          if request.url.lowercased().contains(query) { return true }
          if request.method.lowercased().contains(query) { return true }
        }
        return false
      }
    }

    // Apply method filter (HTTP flows only)
    if let method = methodFilter {
      result = result.filter { $0.request?.method == method }
    }

    // Apply status filter
    switch statusFilter {
    case .all:
      break
    case .success:
      result = result.filter { $0.response?.isSuccess ?? false }
    case .redirect:
      result = result.filter {
        guard let status = $0.response?.statusCode else { return false }
        return status >= 300 && status < 400
      }
    case .clientError:
      result = result.filter {
        guard let status = $0.response?.statusCode else { return false }
        return status >= 400 && status < 500
      }
    case .serverError:
      result = result.filter {
        guard let status = $0.response?.statusCode else { return false }
        return status >= 500
      }
    case .pending:
      result = result.filter { !$0.isComplete }
    case .error:
      result = result.filter { $0.error != nil }
    }

    return result
  }

  /// Unique HTTP methods in captured flows.
  public var availableMethods: [String] {
    Array(Set(flows.compactMap { $0.request?.method })).sorted()
  }

  /// Statistics about captured flows.
  public var statistics: FlowStatistics {
    let total = flows.count
    let successful = flows.filter { $0.response?.isSuccess ?? false }.count
    let failed = flows.filter { $0.response?.isError ?? false }.count
    let pending = flows.filter { !$0.isComplete }.count
    let errors = flows.filter { $0.error != nil }.count

    let totalBytes = flows.reduce(Int64(0)) { sum, flow in
      let httpBytes = Int64(flow.request?.bodySize ?? 0) + Int64(flow.response?.bodySize ?? 0)
      return sum + flow.bytesIn + flow.bytesOut + httpBytes
    }

    let avgDuration =
      flows.compactMap { $0.duration }.reduce(0, +)
      / Double(max(1, flows.filter { $0.duration != nil }.count))

    return FlowStatistics(
      total: total,
      successful: successful,
      failed: failed,
      pending: pending,
      errors: errors,
      totalBytes: Int(min(totalBytes, Int64(Int.max))),
      averageDuration: avgDuration
    )
  }
}
