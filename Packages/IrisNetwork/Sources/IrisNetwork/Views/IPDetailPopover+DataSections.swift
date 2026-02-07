import SwiftUI

// MARK: - Ports, Hostnames, Vulnerabilities, Tags Sections

extension IPDetailPopover {

    // MARK: - Ports Section

    func portsSection(_ ports: [UInt16]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Open Ports (\(ports.count))", systemImage: "network")
                .font(.headline)
                .foregroundColor(.primary)

            FlowLayout(spacing: 6) {
                ForEach(ports.sorted(), id: \.self) { port in
                    PortBadge(port: port)
                }
            }
        }
    }

    // MARK: - Hostnames Section

    func hostnamesSection(_ hostnames: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Hostnames (\(hostnames.count))", systemImage: "globe")
                .font(.headline)
                .foregroundColor(.primary)

            VStack(alignment: .leading, spacing: 4) {
                ForEach(hostnames, id: \.self) { hostname in
                    Text(hostname)
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
    }

    // MARK: - Vulnerabilities Section

    func vulnerabilitiesSection(_ cves: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Vulnerabilities (\(cves.count))", systemImage: "exclamationmark.shield.fill")
                .font(.headline)
                .foregroundColor(.red)

            FlowLayout(spacing: 6) {
                ForEach(cves, id: \.self) { cve in
                    CVEBadge(cve: cve)
                }
            }
        }
    }

    // MARK: - Tags Section

    func tagsSection(_ tags: [String]) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Service Tags", systemImage: "tag.fill")
                .font(.headline)
                .foregroundColor(.primary)

            FlowLayout(spacing: 6) {
                ForEach(tags, id: \.self) { tag in
                    ServiceTagBadge(tag: tag)
                }
            }
        }
    }
}
