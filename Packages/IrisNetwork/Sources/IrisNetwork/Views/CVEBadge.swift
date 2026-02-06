import SwiftUI
import AppKit

/// Badge displaying a CVE identifier with link to NVD details
struct CVEBadge: View {
    let cve: String
    @State private var isHovering = false

    var body: some View {
        Button {
            // Open CVE details on NVD
            let urlString = "https://nvd.nist.gov/vuln/detail/\(cve)"
            if let url = URL(string: urlString) {
                NSWorkspace.shared.open(url)
            }
        } label: {
            Text(cve)
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .background(Color.red.opacity(isHovering ? 0.3 : 0.2))
                .foregroundColor(.red)
                .cornerRadius(4)
        }
        .buttonStyle(.plain)
        .pointerCursor()
        .onHover { isHovering = $0 }
        .help("View CVE details on NVD")
    }
}
