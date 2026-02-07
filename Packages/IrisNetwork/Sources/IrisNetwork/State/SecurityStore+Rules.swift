import Foundation

// MARK: - Rule Management

@MainActor
extension SecurityStore {

    /// Add a new security rule
    public func addRule(_ rule: SecurityRule) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? NetworkXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        let encoder = JSONEncoder()
        guard let data = try? encoder.encode(rule) else {
            errorMessage = "Failed to encode rule"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.addRule(data) { [weak self] success, error in
                Task { @MainActor in
                    if let error = error {
                        self?.errorMessage = error
                    }
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    /// Remove a rule by ID
    public func removeRule(_ ruleId: UUID) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? NetworkXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.removeRule(ruleId.uuidString) { [weak self] success in
                Task { @MainActor in
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    /// Toggle a rule's enabled state
    public func toggleRule(_ ruleId: UUID) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? NetworkXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.toggleRule(ruleId.uuidString) { [weak self] success in
                Task { @MainActor in
                    if success {
                        await self?.fetchRules()
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    // MARK: - Quick Actions

    /// Block all connections from a process
    public func blockProcess(path: String) async -> Bool {
        let rule = SecurityRule.blockProcess(path: path)
        return await addRule(rule)
    }

    /// Allow all connections from a process
    public func allowProcess(path: String) async -> Bool {
        let rule = SecurityRule.allowProcess(path: path)
        return await addRule(rule)
    }
}
