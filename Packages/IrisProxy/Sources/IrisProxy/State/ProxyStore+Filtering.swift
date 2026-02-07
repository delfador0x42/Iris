import Foundation
import Combine

// MARK: - Filtering, Statistics & Search

@MainActor
extension ProxyStore {

    // MARK: - Search Debounce

    func setupSearchDebounce() {
        // Debounce search queries
        $searchQuery
            .debounce(for: .milliseconds(300), scheduler: RunLoop.main)
            .sink { [weak self] _ in
                self?.objectWillChange.send()
            }
            .store(in: &cancellables)
    }

    // MARK: - Filtered Flows

    /// Flows filtered by current search query and filters.
    public var filteredFlows: [ProxyCapturedFlow] {
        var result = flows

        // Apply search query
        if !searchQuery.isEmpty {
            let query = searchQuery.lowercased()
            result = result.filter { flow in
                flow.request.url.lowercased().contains(query) ||
                flow.request.method.lowercased().contains(query) ||
                (flow.processName?.lowercased().contains(query) ?? false)
            }
        }

        // Apply method filter
        if let method = methodFilter {
            result = result.filter { $0.request.method == method }
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
            result = result.filter { $0.response == nil && $0.error == nil }
        case .error:
            result = result.filter { $0.error != nil }
        }

        return result
    }

    /// Unique methods in captured flows.
    public var availableMethods: [String] {
        Array(Set(flows.map { $0.request.method })).sorted()
    }

    /// Statistics about captured flows.
    public var statistics: FlowStatistics {
        let total = flows.count
        let successful = flows.filter { $0.response?.isSuccess ?? false }.count
        let failed = flows.filter { $0.response?.isError ?? false }.count
        let pending = flows.filter { $0.response == nil && $0.error == nil }.count
        let errors = flows.filter { $0.error != nil }.count

        let totalBytes = flows.reduce(0) { sum, flow in
            sum + flow.request.bodySize + (flow.response?.bodySize ?? 0)
        }

        let avgDuration = flows.compactMap { $0.duration }.reduce(0, +) /
            Double(max(1, flows.filter { $0.duration != nil }.count))

        return FlowStatistics(
            total: total,
            successful: successful,
            failed: failed,
            pending: pending,
            errors: errors,
            totalBytes: totalBytes,
            averageDuration: avgDuration
        )
    }
}
