import SwiftUI

/// View for managing all firewall rules
struct RulesListView: View {
    @EnvironmentObject private var store: SecurityStore
    @State private var filter: RuleFilter = .all

    enum RuleFilter: String, CaseIterable {
        case all = "All"
        case active = "Active"
        case blocked = "Blocked"
        case allowed = "Allowed"
    }

    private var filteredRules: [SecurityRule] {
        switch filter {
        case .all: return store.rules
        case .active: return store.rules.filter { $0.isActive }
        case .blocked: return store.rules.filter { $0.action == .block }
        case .allowed: return store.rules.filter { $0.action == .allow }
        }
    }

    /// Group rules by process identity key
    private var groupedRules: [(key: String, rules: [SecurityRule])] {
        let grouped = Dictionary(grouping: filteredRules) { $0.key }
        return grouped.map { (key: $0.key, rules: $0.value) }
            .sorted { $0.key < $1.key }
    }

    var body: some View {
        VStack(spacing: 0) {
            // Filter bar
            filterBar
            Divider().background(Color.gray.opacity(0.3))

            if store.rules.isEmpty {
                emptyState
            } else {
                rulesList
            }
        }
    }

    // MARK: - Filter Bar

    private var filterBar: some View {
        HStack(spacing: 12) {
            ForEach(RuleFilter.allCases, id: \.self) { f in
                Button(f.rawValue) { filter = f }
                    .buttonStyle(.plain)
                    .font(.system(size: 12, weight: filter == f ? .bold : .regular))
                    .foregroundColor(filter == f ? .white : .gray)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4)
                    .background(filter == f ? Color.blue.opacity(0.3) : Color.clear)
                    .cornerRadius(6)
            }

            Spacer()

            Text("\(filteredRules.count) rules")
                .font(.system(size: 11))
                .foregroundColor(.gray)

            if !store.rules.isEmpty {
                Button("Clear All") {
                    Task {
                        for rule in store.rules {
                            _ = await store.removeRule(rule.id)
                        }
                    }
                }
                .font(.system(size: 11))
                .foregroundColor(.red.opacity(0.8))
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.black.opacity(0.3))
    }

    // MARK: - Empty State

    private var emptyState: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.slash")
                .font(.system(size: 48))
                .foregroundColor(.gray)

            Text("No firewall rules")
                .font(.headline)
                .foregroundColor(.white)

            Text("Allow or block connections from the connection list")
                .font(.system(size: 14))
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Rules List

    private var rulesList: some View {
        ThemedScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(groupedRules, id: \.key) { group in
                    ruleGroupHeader(group.key, count: group.rules.count)

                    ForEach(group.rules) { rule in
                        ruleRow(rule)
                        Divider().background(Color.gray.opacity(0.15))
                    }
                }
            }
            .padding()
        }
    }

    private func ruleGroupHeader(_ key: String, count: Int) -> some View {
        HStack(spacing: 8) {
            Image(systemName: "app.fill")
                .foregroundColor(.blue)
                .font(.system(size: 12))

            Text(processName(for: key))
                .font(.system(size: 13, weight: .semibold))
                .foregroundColor(.white)

            Text("\(count)")
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(.gray)
                .padding(.horizontal, 5)
                .padding(.vertical, 1)
                .background(Color.white.opacity(0.1))
                .cornerRadius(3)

            Spacer()
        }
        .padding(.vertical, 6)
        .padding(.top, 8)
    }

    private func ruleRow(_ rule: SecurityRule) -> some View {
        HStack(spacing: 12) {
            Spacer().frame(width: 20)

            // Action badge
            Text(rule.action.displayName)
                .font(.system(size: 11, weight: .bold))
                .foregroundColor(rule.action == .allow ? .green : .red)
                .frame(width: 50)

            // Scope + endpoint
            VStack(alignment: .leading, spacing: 2) {
                Text(rule.scope.displayName)
                    .font(.system(size: 11))
                    .foregroundColor(.gray)

                if rule.scope == .endpoint {
                    let addr = rule.remoteAddress ?? "*"
                    let port = rule.remotePort ?? "*"
                    Text("\(addr):\(port)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.white.opacity(0.8))
                }
            }

            Spacer()

            // Enabled toggle
            Toggle("", isOn: Binding(
                get: { rule.isEnabled },
                set: { _ in
                    Task { _ = await store.toggleRule(rule.id) }
                }
            ))
            .toggleStyle(.switch)
            .scaleEffect(0.7)
            .frame(width: 40)

            // Delete
            Button {
                Task { _ = await store.removeRule(rule.id) }
            } label: {
                Image(systemName: "trash")
                    .foregroundColor(.red.opacity(0.6))
                    .font(.system(size: 11))
            }
            .buttonStyle(.plain)
            .help("Delete rule")
        }
        .padding(.vertical, 4)
        .opacity(rule.isEnabled ? 1.0 : 0.5)
    }

    /// Extract display name from identity key (signing ID or path basename)
    private func processName(for key: String) -> String {
        if key.contains("/") {
            return URL(fileURLWithPath: key).lastPathComponent
        }
        // Signing ID like "com.apple.configd" → take last component
        return key.components(separatedBy: ".").last ?? key
    }
}
