import SwiftUI

/// View for managing WiFi preferences (like airport prefs command)
public struct WiFiPreferencesView: View {
    @ObservedObject var store: WiFiStore
    @State private var isLoading = true
    @State private var isSaving = false

    public init(store: WiFiStore) {
        self.store = store
    }

    public var body: some View {
        Form {
            Section("Join Behavior") {
                Picker("Join Mode", selection: joinModeBinding) {
                    ForEach(WiFiJoinMode.allCases, id: \.self) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }
                .help(store.preferences.joinMode.description)

                Picker("Fallback Mode", selection: joinModeFallbackBinding) {
                    ForEach(WiFiJoinMode.allCases, id: \.self) { mode in
                        Text(mode.rawValue).tag(mode)
                    }
                }

                Toggle("Remember Recent Networks", isOn: rememberRecentBinding)

                Toggle("Disconnect on Logout", isOn: disconnectOnLogoutBinding)
            }

            Section("Admin Requirements") {
                Toggle("Require Admin for Ad-hoc (IBSS)", isOn: requireAdminIBSSBinding)

                Toggle("Require Admin for Network Change", isOn: requireAdminNetworkChangeBinding)

                Toggle("Require Admin for Power Toggle", isOn: requireAdminPowerToggleBinding)
            }

            Section {
                Button {
                    Task {
                        isLoading = true
                        await store.refreshPreferences()
                        isLoading = false
                    }
                } label: {
                    HStack {
                        Image(systemName: "arrow.clockwise")
                        Text("Refresh from System")
                    }
                }
                .disabled(isLoading)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("WiFi Preferences")
        .overlay {
            if isLoading {
                ProgressView()
            }
        }
        .task {
            await store.refreshPreferences()
            isLoading = false
        }
    }

    // MARK: - Preference Bindings

    private var joinModeBinding: Binding<WiFiJoinMode> {
        Binding(
            get: { store.preferences.joinMode },
            set: { newValue in
                Task {
                    isSaving = true
                    _ = await store.setPreference(key: "JoinMode", value: newValue.rawValue)
                    isSaving = false
                }
            }
        )
    }

    private var joinModeFallbackBinding: Binding<WiFiJoinMode> {
        Binding(
            get: { store.preferences.joinModeFallback },
            set: { newValue in
                Task {
                    _ = await store.setPreference(key: "JoinModeFallback", value: newValue.rawValue)
                }
            }
        )
    }

    private var rememberRecentBinding: Binding<Bool> {
        Binding(
            get: { store.preferences.rememberRecentNetworks },
            set: { newValue in
                Task {
                    _ = await store.setPreference(key: "RememberRecentNetworks", value: newValue ? "YES" : "NO")
                }
            }
        )
    }

    private var disconnectOnLogoutBinding: Binding<Bool> {
        Binding(
            get: { store.preferences.disconnectOnLogout },
            set: { newValue in
                Task {
                    _ = await store.setPreference(key: "DisconnectOnLogout", value: newValue ? "YES" : "NO")
                }
            }
        )
    }

    private var requireAdminIBSSBinding: Binding<Bool> {
        Binding(
            get: { store.preferences.requireAdminIBSS },
            set: { newValue in
                Task {
                    _ = await store.setPreference(key: "RequireAdminIBSS", value: newValue ? "YES" : "NO")
                }
            }
        )
    }

    private var requireAdminNetworkChangeBinding: Binding<Bool> {
        Binding(
            get: { store.preferences.requireAdminNetworkChange },
            set: { newValue in
                Task {
                    _ = await store.setPreference(key: "RequireAdminNetworkChange", value: newValue ? "YES" : "NO")
                }
            }
        )
    }

    private var requireAdminPowerToggleBinding: Binding<Bool> {
        Binding(
            get: { store.preferences.requireAdminPowerToggle },
            set: { newValue in
                Task {
                    _ = await store.setPreference(key: "RequireAdminPowerToggle", value: newValue ? "YES" : "NO")
                }
            }
        )
    }
}

#Preview {
    WiFiPreferencesView(store: WiFiStore())
        .frame(width: 400, height: 500)
}
