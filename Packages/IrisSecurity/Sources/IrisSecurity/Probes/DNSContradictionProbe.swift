import Foundation
import Network
import os.log

/// Three-way DNS: system resolver (mDNSResponder) vs direct UDP to 8.8.8.8 vs DoH to Cloudflare.
/// A DNS hijacker must intercept all 3 paths simultaneously to avoid detection.
public actor DNSContradictionProbe: ContradictionProbe {
    public static let shared = DNSContradictionProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "DNSContradictionProbe")

    public nonisolated let id = "dns-contradiction"
    public nonisolated let name = "DNS Resolution"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "DNS resolution returns the correct IP for a domain",
        groundTruth: "System resolver (getaddrinfo via mDNSResponder), direct UDP to Google DNS (8.8.8.8), HTTPS DoH to Cloudflare",
        adversaryCost: "Must intercept 3 independent resolution paths: local resolver daemon, raw UDP to external server, HTTPS to DoH endpoint",
        positiveDetection: "Shows resolved IPs per source — flags when system resolver returns IP that no external source confirms",
        falsePositiveRate: "Low for well-known domains. CDN domains may legitimately differ — only flags system-unique IPs"
    )

    // Domains to probe — mix of infrastructure and well-known
    private let testDomains = ["apple.com", "google.com", "example.com"]

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false

        for domain in testDomains {
            // Source 1: System resolver (getaddrinfo → mDNSResponder)
            let systemIPs = resolveViaSystem(domain)

            // Source 2: Direct UDP to Google DNS
            let directIPs = await resolveViaDirectUDP(domain)

            // Source 3: DoH via Cloudflare
            let dohIPs = await resolveViaDoH(domain)

            // Check: system resolver returned IP not seen in ANY external source
            let externalAll = directIPs.union(dohIPs)
            let systemOnly = systemIPs.subtracting(externalAll)

            // System vs Direct UDP
            if !systemIPs.isEmpty && !directIPs.isEmpty {
                let match = systemOnly.isEmpty
                if !match { hasContradiction = true }
                comparisons.append(SourceComparison(
                    label: "\(domain): system vs direct UDP",
                    sourceA: SourceValue("getaddrinfo()", formatIPs(systemIPs)),
                    sourceB: SourceValue("UDP 8.8.8.8:53", formatIPs(directIPs)),
                    matches: match))
            }

            // System vs DoH
            if !systemIPs.isEmpty && !dohIPs.isEmpty {
                let match = systemOnly.isEmpty
                if !match { hasContradiction = true }
                comparisons.append(SourceComparison(
                    label: "\(domain): system vs DoH",
                    sourceA: SourceValue("getaddrinfo()", formatIPs(systemIPs)),
                    sourceB: SourceValue("DoH cloudflare", formatIPs(dohIPs)),
                    matches: match))
            }

            // Direct UDP vs DoH (cross-check external sources)
            if !directIPs.isEmpty && !dohIPs.isEmpty {
                // External sources may differ for CDN, that's fine
                // Only flag if they have zero overlap (suggests interception)
                let overlap = !directIPs.isDisjoint(with: dohIPs)
                comparisons.append(SourceComparison(
                    label: "\(domain): direct UDP vs DoH",
                    sourceA: SourceValue("UDP 8.8.8.8:53", formatIPs(directIPs)),
                    sourceB: SourceValue("DoH cloudflare", formatIPs(dohIPs)),
                    matches: overlap))
                if !overlap { hasContradiction = true }
            }
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)

        let verdict: ProbeVerdict
        let message: String
        if comparisons.isEmpty {
            verdict = .degraded
            message = "Could not resolve via enough sources"
        } else if hasContradiction {
            verdict = .contradiction
            let mismatches = comparisons.filter { !$0.matches }.count
            message = "CONTRADICTION: \(mismatches) DNS resolution disagreement(s) — possible DNS hijack"
            logger.critical("DNS CONTRADICTION: \(mismatches) mismatches")
        } else {
            verdict = .consistent
            message = "DNS resolution consistent across \(comparisons.count) comparisons"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - Source 1: System resolver

    private func resolveViaSystem(_ domain: String) -> Set<String> {
        var result = Set<String>()
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        hints.ai_socktype = SOCK_STREAM

        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(domain, nil, &hints, &res) == 0, let info = res else { return result }
        defer { freeaddrinfo(info) }

        var cur: UnsafeMutablePointer<addrinfo>? = info
        while let ai = cur {
            if let ip = sockaddrToString(ai.pointee.ai_addr, length: ai.pointee.ai_addrlen) {
                result.insert(ip)
            }
            cur = ai.pointee.ai_next
        }
        return result
    }

    // MARK: - Source 2: Direct UDP to 8.8.8.8

    private func resolveViaDirectUDP(_ domain: String) async -> Set<String> {
        // Build DNS query packet
        let packet = buildDNSQuery(domain: domain, txid: UInt16.random(in: 1...0xFFFF))

        return await withCheckedContinuation { cont in
            let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            guard fd >= 0 else {
                cont.resume(returning: [])
                return
            }

            // Set 3s timeout
            var tv = timeval(tv_sec: 3, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            var addr = sockaddr_in()
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = UInt16(53).bigEndian
            addr.sin_addr.s_addr = inet_addr("8.8.8.8")

            let sent = packet.withUnsafeBytes { buf in
                withUnsafePointer(to: &addr) { ptr in
                    ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        sendto(fd, buf.baseAddress, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
            }

            guard sent > 0 else {
                close(fd)
                cont.resume(returning: [])
                return
            }

            var buffer = [UInt8](repeating: 0, count: 512)
            let received = recv(fd, &buffer, buffer.count, 0)
            close(fd)

            guard received > 12 else {
                cont.resume(returning: [])
                return
            }

            let ips = parseDNSResponse(Array(buffer.prefix(received)))
            cont.resume(returning: ips)
        }
    }

    // MARK: - Source 3: DNS-over-HTTPS via Cloudflare

    private func resolveViaDoH(_ domain: String) async -> Set<String> {
        guard let url = URL(string: "https://cloudflare-dns.com/dns-query?name=\(domain)&type=A") else { return [] }

        var request = URLRequest(url: url)
        request.setValue("application/dns-json", forHTTPHeaderField: "Accept")
        request.timeoutInterval = 5

        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            guard let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let answers = json["Answer"] as? [[String: Any]] else { return [] }

            var result = Set<String>()
            for answer in answers {
                if let type = answer["type"] as? Int, type == 1,  // A record
                   let ip = answer["data"] as? String {
                    result.insert(ip)
                }
            }
            return result
        } catch {
            logger.warning("DoH query failed: \(error.localizedDescription)")
            return []
        }
    }

    // MARK: - DNS Wire Format

    private func buildDNSQuery(domain: String, txid: UInt16) -> Data {
        var data = Data()
        // Header: TXID, flags=0x0100 (standard query, RD=1), QDCOUNT=1
        data.append(contentsOf: withUnsafeBytes(of: txid.bigEndian) { Array($0) })
        data.append(contentsOf: [0x01, 0x00]) // flags: standard query, recursion desired
        data.append(contentsOf: [0x00, 0x01]) // QDCOUNT = 1
        data.append(contentsOf: [0x00, 0x00]) // ANCOUNT = 0
        data.append(contentsOf: [0x00, 0x00]) // NSCOUNT = 0
        data.append(contentsOf: [0x00, 0x00]) // ARCOUNT = 0

        // QNAME: length-prefixed labels
        for label in domain.split(separator: ".") {
            data.append(UInt8(label.utf8.count))
            data.append(contentsOf: label.utf8)
        }
        data.append(0) // root label

        // QTYPE = A (1), QCLASS = IN (1)
        data.append(contentsOf: [0x00, 0x01])
        data.append(contentsOf: [0x00, 0x01])

        return data
    }

    private func parseDNSResponse(_ bytes: [Int]) -> Set<String> {
        // This overload handles the actual byte array from recv
        return parseDNSResponse(bytes.map { UInt8(clamping: $0) })
    }

    private func parseDNSResponse(_ bytes: [UInt8]) -> Set<String> {
        guard bytes.count > 12 else { return [] }

        let ancount = (UInt16(bytes[6]) << 8) | UInt16(bytes[7])
        guard ancount > 0 else { return [] }

        // Skip header (12 bytes) + question section
        var offset = 12
        // Skip QNAME
        while offset < bytes.count {
            let len = Int(bytes[offset])
            if len == 0 { offset += 1; break }
            if len >= 0xC0 { offset += 2; break } // pointer
            offset += 1 + len
        }
        offset += 4 // skip QTYPE + QCLASS

        // Parse answer records
        var result = Set<String>()
        for _ in 0..<ancount {
            guard offset + 12 <= bytes.count else { break }
            // Skip NAME (may be pointer)
            if bytes[offset] >= 0xC0 {
                offset += 2
            } else {
                while offset < bytes.count && bytes[offset] != 0 { offset += 1 + Int(bytes[offset]) }
                offset += 1
            }
            guard offset + 10 <= bytes.count else { break }

            let rtype = (UInt16(bytes[offset]) << 8) | UInt16(bytes[offset + 1])
            let rdlength = Int((UInt16(bytes[offset + 8]) << 8) | UInt16(bytes[offset + 9]))
            offset += 10

            if rtype == 1 && rdlength == 4 && offset + 4 <= bytes.count {
                let ip = "\(bytes[offset]).\(bytes[offset+1]).\(bytes[offset+2]).\(bytes[offset+3])"
                result.insert(ip)
            }
            offset += rdlength
        }
        return result
    }

    // MARK: - Helpers

    private func sockaddrToString(_ addr: UnsafePointer<sockaddr>, length: socklen_t) -> String? {
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(addr, length, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: host)
    }

    private func formatIPs(_ ips: Set<String>) -> String {
        ips.sorted().prefix(4).joined(separator: ",")
    }
}
