import Foundation
import CryptoKit
import os.log

/// Verdict from VirusTotal analysis
public struct VTVerdict: Sendable {
    public let sha256: String
    public let malicious: Int
    public let suspicious: Int
    public let undetected: Int
    public let harmless: Int
    public let found: Bool

    public var isMalicious: Bool { malicious > 0 }
    public var totalEngines: Int { malicious + suspicious + undetected + harmless }
    public var summary: String {
        guard found else { return "not found on VirusTotal" }
        if malicious > 0 { return "\(malicious)/\(totalEngines) engines flagged malicious" }
        if suspicious > 0 { return "\(suspicious)/\(totalEngines) engines flagged suspicious" }
        return "clean (\(totalEngines) engines)"
    }
}

/// Checks file hashes and uploads suspicious binaries to VirusTotal v3 API.
public actor VirusTotalService {
    public static let shared = VirusTotalService()
    private let logger = Logger(subsystem: "com.wudan.iris", category: "VirusTotal")
    private let baseURL = "https://www.virustotal.com/api/v3"
    private var apiKey: String?
    private var cache: [String: VTVerdict] = [:]

    public func configure(apiKey: String) {
        self.apiKey = apiKey
    }

    /// Load API key from ~/Library/Application Support/Iris/vt_api_key
    public func loadKey() -> Bool {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let keyFile = support.appendingPathComponent("Iris/vt_api_key")
        if let key = try? String(contentsOf: keyFile, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
           !key.isEmpty {
            apiKey = key
            return true
        }
        return false
    }

    /// Save API key to disk
    public func saveKey(_ key: String) throws {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let dir = support.appendingPathComponent("Iris")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        try key.write(to: dir.appendingPathComponent("vt_api_key"), atomically: true, encoding: .utf8)
        apiKey = key
    }

    // MARK: - Hash a file

    public func sha256(of path: String) -> String? {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else { return nil }
        let digest = SHA256.hash(data: data)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Check hash against VT

    public func checkHash(_ hash: String) async -> VTVerdict? {
        if let cached = cache[hash] { return cached }
        guard let key = apiKey else {
            logger.warning("No VT API key configured")
            return nil
        }

        let url = URL(string: "\(baseURL)/files/\(hash)")!
        var req = URLRequest(url: url)
        req.setValue(key, forHTTPHeaderField: "x-apikey")
        req.timeoutInterval = 15

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0

            if status == 404 {
                let verdict = VTVerdict(sha256: hash, malicious: 0, suspicious: 0,
                                        undetected: 0, harmless: 0, found: false)
                cache[hash] = verdict
                return verdict
            }
            guard status == 200 else {
                logger.error("VT API error: HTTP \(status)")
                return nil
            }

            return parseResponse(data, hash: hash)
        } catch {
            logger.error("VT request failed: \(error.localizedDescription)")
            return nil
        }
    }

    // MARK: - Check a file (hash first, upload if unknown)

    public func checkFile(_ path: String, upload: Bool = false) async -> VTVerdict? {
        guard let hash = sha256(of: path) else { return nil }

        if let verdict = await checkHash(hash) {
            if verdict.found || !upload { return verdict }
        }

        // Not found — upload if requested
        if upload {
            return await uploadFile(path, hash: hash)
        }

        return VTVerdict(sha256: hash, malicious: 0, suspicious: 0,
                         undetected: 0, harmless: 0, found: false)
    }

    // MARK: - Upload file

    public func uploadFile(_ path: String, hash: String? = nil) async -> VTVerdict? {
        guard let key = apiKey else { return nil }
        let fileURL = URL(fileURLWithPath: path)
        guard let fileData = try? Data(contentsOf: fileURL) else { return nil }

        // VT file size limit for direct upload: 32MB
        guard fileData.count <= 32 * 1024 * 1024 else {
            logger.warning("File too large for VT upload: \(path)")
            return nil
        }

        let boundary = UUID().uuidString
        var body = Data()
        body.append("--\(boundary)\r\n".data(using: .utf8)!)
        body.append("Content-Disposition: form-data; name=\"file\"; filename=\"\(fileURL.lastPathComponent)\"\r\n".data(using: .utf8)!)
        body.append("Content-Type: application/octet-stream\r\n\r\n".data(using: .utf8)!)
        body.append(fileData)
        body.append("\r\n--\(boundary)--\r\n".data(using: .utf8)!)

        let url = URL(string: "\(baseURL)/files")!
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue(key, forHTTPHeaderField: "x-apikey")
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        req.httpBody = body
        req.timeoutInterval = 60

        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            guard status == 200 else {
                logger.error("VT upload failed: HTTP \(status)")
                return nil
            }

            logger.info("Uploaded \(path) to VT")

            // Upload returns analysis ID, not results yet
            // Parse the analysis ID and return a pending verdict
            let h = hash ?? sha256(of: path) ?? ""
            let verdict = VTVerdict(sha256: h, malicious: 0, suspicious: 0,
                                     undetected: 0, harmless: 0, found: false)
            return verdict
        } catch {
            logger.error("VT upload error: \(error.localizedDescription)")
            return nil
        }
    }

    // MARK: - Batch check findings

    public func checkFindings(_ anomalies: [ProcessAnomaly]) async -> [String: VTVerdict] {
        var results: [String: VTVerdict] = [:]
        var seen = Set<String>()

        for anomaly in anomalies {
            let path = anomaly.processPath
            guard !path.isEmpty, !seen.contains(path) else { continue }
            seen.insert(path)

            guard FileManager.default.fileExists(atPath: path) else { continue }
            if let verdict = await checkFile(path) {
                results[path] = verdict
            }
        }
        return results
    }

    // MARK: - Parse VT response

    private func parseResponse(_ data: Data, hash: String) -> VTVerdict? {
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let attrs = (json["data"] as? [String: Any])?["attributes"] as? [String: Any],
              let stats = attrs["last_analysis_stats"] as? [String: Any] else { return nil }

        let verdict = VTVerdict(
            sha256: hash,
            malicious: stats["malicious"] as? Int ?? 0,
            suspicious: stats["suspicious"] as? Int ?? 0,
            undetected: stats["undetected"] as? Int ?? 0,
            harmless: stats["harmless"] as? Int ?? 0,
            found: true
        )
        cache[hash] = verdict
        return verdict
    }
}
