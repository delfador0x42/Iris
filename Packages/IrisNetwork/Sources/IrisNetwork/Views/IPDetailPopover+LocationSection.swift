import SwiftUI

// MARK: - General Information / Location Section

extension IPDetailPopover {

    var locationSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("General Information", systemImage: "info.circle.fill")
                .font(.headline)
                .foregroundColor(.primary)

            VStack(alignment: .leading, spacing: 8) {
                // Hostnames
                if let hostnames = connection.remoteHostnames, !hostnames.isEmpty {
                    InfoRow(label: "Hostnames") {
                        VStack(alignment: .leading, spacing: 2) {
                            ForEach(hostnames.prefix(5), id: \.self) { hostname in
                                Text(hostname)
                                    .font(.system(size: 12, design: .monospaced))
                                    .textSelection(.enabled)
                            }
                            if hostnames.count > 5 {
                                Text("+\(hostnames.count - 5) more")
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }
                    }
                } else if let hostname = connection.remoteHostname {
                    SimpleInfoRow(label: "Hostname", value: hostname)
                }

                // Domains (extracted from hostnames)
                let domains = extractDomains()
                if !domains.isEmpty {
                    InfoRow(label: "Domains") {
                        FlowLayout(spacing: 4) {
                            ForEach(domains, id: \.self) { domain in
                                Text(domain)
                                    .font(.system(size: 11, design: .monospaced))
                                    .padding(.horizontal, 6)
                                    .padding(.vertical, 2)
                                    .background(Color.blue.opacity(0.15))
                                    .cornerRadius(4)
                            }
                        }
                    }
                }

                Divider()

                // Country
                if let country = connection.remoteCountry {
                    InfoRow(label: "Country") {
                        HStack(spacing: 6) {
                            if let code = connection.remoteCountryCode {
                                Text(countryFlag(for: code))
                            }
                            Text(country)
                                .font(.system(size: 12))
                        }
                    }
                }

                // City
                if let city = connection.remoteCity, !city.isEmpty {
                    SimpleInfoRow(label: "City", value: city)
                }

                Divider()

                // Organization / ISP
                if let org = connection.remoteOrganization {
                    SimpleInfoRow(label: "Organization", value: org)
                }

                // ASN
                if let asn = connection.remoteASN {
                    SimpleInfoRow(label: "ASN", value: asn)
                }
            }
        }
    }

    /// Extract unique domains from hostnames
    func extractDomains() -> [String] {
        guard let hostnames = connection.remoteHostnames else { return [] }

        var domains = Set<String>()
        for hostname in hostnames {
            let parts = hostname.split(separator: ".")
            if parts.count >= 2 {
                // Get last two parts as domain (e.g., github.com from www.github.com)
                let domain = parts.suffix(2).joined(separator: ".")
                domains.insert(domain)
            }
        }
        return Array(domains).sorted()
    }

    /// Convert country code to flag emoji
    func countryFlag(for code: String) -> String {
        let base: UInt32 = 127397
        var flag = ""
        for scalar in code.uppercased().unicodeScalars {
            if let flagScalar = UnicodeScalar(base + scalar.value) {
                flag.append(Character(flagScalar))
            }
        }
        return flag
    }
}
