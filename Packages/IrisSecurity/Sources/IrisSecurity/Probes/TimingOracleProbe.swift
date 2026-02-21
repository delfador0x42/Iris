import Foundation
import os.log

/// System clock vs multiple NTP sources.
/// A time-manipulation attack (to extend certificates, bypass token expiry) must defeat
/// all NTP servers simultaneously or be caught by clock drift detection.
public actor TimingOracleProbe: ContradictionProbe {
    public static let shared = TimingOracleProbe()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "TimingOracleProbe")

    public nonisolated let id = "timing-oracle"
    public nonisolated let name = "Timing Oracle"

    public nonisolated let metadata = ProbeMetadata(
        whatLie: "The system clock reflects real time",
        groundTruth: "Query 4 independent NTP servers (Apple, Google, Cloudflare, pool.ntp.org), compare against system Date()",
        adversaryCost: "Must intercept NTP packets to 4 servers on different networks, or patch the kernel clock source itself",
        positiveDetection: "Shows system time vs NTP consensus and per-server delta",
        falsePositiveRate: "Very low — threshold is 5 seconds, normal NTP jitter is <200ms"
    )

    private let ntpServers = [
        "time.apple.com",
        "time.google.com",
        "time.cloudflare.com",
        "pool.ntp.org",
    ]

    // NTP epoch starts 1900-01-01, Unix epoch starts 1970-01-01
    private let ntpUnixDelta: UInt32 = 2_208_988_800
    private let driftThreshold: TimeInterval = 5.0

    public func run() async -> ProbeResult {
        let start = Date()
        var comparisons: [SourceComparison] = []
        var hasContradiction = false
        var ntpTimes: [(server: String, time: Date)] = []

        // Query each NTP server
        for server in ntpServers {
            if let ntpTime = await queryNTP(server: server) {
                ntpTimes.append((server, ntpTime))
            }
        }

        let systemTime = Date()

        // Compare system time against each NTP server
        for (server, ntpTime) in ntpTimes {
            let delta = abs(systemTime.timeIntervalSince(ntpTime))
            let match = delta < driftThreshold

            if !match { hasContradiction = true }

            comparisons.append(SourceComparison(
                label: "system clock vs \(server)",
                sourceA: SourceValue("Date()", formatTime(systemTime)),
                sourceB: SourceValue("NTP \(server)", formatTime(ntpTime)),
                matches: match))
        }

        // Cross-check: NTP servers should agree with each other (within 2s)
        if ntpTimes.count >= 2 {
            for i in 0..<(ntpTimes.count - 1) {
                let a = ntpTimes[i]
                let b = ntpTimes[i + 1]
                let delta = abs(a.time.timeIntervalSince(b.time))
                let match = delta < 2.0

                if !match { hasContradiction = true }

                comparisons.append(SourceComparison(
                    label: "\(a.server) vs \(b.server)",
                    sourceA: SourceValue("NTP \(a.server)", formatTime(a.time)),
                    sourceB: SourceValue("NTP \(b.server)", formatTime(b.time)),
                    matches: match))
            }
        }

        let durationMs = Int(Date().timeIntervalSince(start) * 1000)

        let verdict: ProbeVerdict
        let message: String
        if ntpTimes.isEmpty {
            verdict = .degraded
            message = "Could not reach any NTP servers — network may be restricted"
        } else if hasContradiction {
            verdict = .contradiction
            let mismatches = comparisons.filter { !$0.matches }.count
            message = "CONTRADICTION: \(mismatches) timing disagreement(s) — possible clock manipulation"
            logger.critical("TIMING CONTRADICTION: \(mismatches) clock mismatches")
        } else {
            verdict = .consistent
            let avgDelta = ntpTimes.map { abs(systemTime.timeIntervalSince($0.time)) }
                .reduce(0, +) / Double(ntpTimes.count)
            message = "System clock consistent with \(ntpTimes.count) NTP sources (avg drift: \(String(format: "%.1f", avgDelta * 1000))ms)"
        }

        return ProbeResult(
            probeId: id, probeName: name, verdict: verdict,
            comparisons: comparisons, message: message, durationMs: durationMs)
    }

    // MARK: - NTP Query

    private func queryNTP(server: String) async -> Date? {
        return await withCheckedContinuation { cont in
            // Resolve server address
            var hints = addrinfo()
            hints.ai_family = AF_INET
            hints.ai_socktype = SOCK_DGRAM

            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(server, "123", &hints, &res) == 0, let info = res else {
                cont.resume(returning: nil)
                return
            }
            defer { freeaddrinfo(info) }

            let fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            guard fd >= 0 else {
                cont.resume(returning: nil)
                return
            }

            // 3s timeout
            var tv = timeval(tv_sec: 3, tv_usec: 0)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            // Build 48-byte NTP packet: LI=0, VN=4, Mode=3 (client)
            var packet = [UInt8](repeating: 0, count: 48)
            packet[0] = 0x23 // 00_100_011 = LI:0, VN:4, Mode:3

            // Send
            let sent = sendto(fd, &packet, packet.count, 0, info.pointee.ai_addr, info.pointee.ai_addrlen)
            guard sent == 48 else {
                close(fd)
                cont.resume(returning: nil)
                return
            }

            // Receive
            var response = [UInt8](repeating: 0, count: 48)
            let received = recv(fd, &response, response.count, 0)
            close(fd)

            guard received == 48 else {
                cont.resume(returning: nil)
                return
            }

            // Parse T3 (transmit timestamp) at bytes 40-47
            // Top 4 bytes = seconds since 1900-01-01, bottom 4 = fraction
            let seconds = UInt32(response[40]) << 24
                        | UInt32(response[41]) << 16
                        | UInt32(response[42]) << 8
                        | UInt32(response[43])
            let fraction = UInt32(response[44]) << 24
                         | UInt32(response[45]) << 16
                         | UInt32(response[46]) << 8
                         | UInt32(response[47])

            guard seconds > ntpUnixDelta else {
                cont.resume(returning: nil)
                return
            }

            let unixSeconds = Double(seconds - ntpUnixDelta) + Double(fraction) / 4_294_967_296.0
            cont.resume(returning: Date(timeIntervalSince1970: unixSeconds))
        }
    }

    // MARK: - Helpers

    private func formatTime(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return f.string(from: date)
    }
}
