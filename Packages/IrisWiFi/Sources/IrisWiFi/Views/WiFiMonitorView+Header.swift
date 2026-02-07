import SwiftUI

extension WiFiMonitorView {

    // MARK: - Header

    var headerSection: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("WiFi Monitor")
                    .font(.system(size: 28, weight: .bold, design: .serif))
                    .foregroundColor(.white)

                if let info = store.interfaceInfo {
                    Text("Interface: \(info.id)")
                        .font(.caption)
                        .foregroundColor(.gray)
                }
            }

            Spacer()

            // Power toggle
            Toggle("", isOn: Binding(
                get: { store.isPoweredOn },
                set: { newValue in
                    Task {
                        await store.setPower(newValue)
                    }
                }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
        }
    }
}
