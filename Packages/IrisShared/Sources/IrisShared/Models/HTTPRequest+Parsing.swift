import Foundation

// MARK: - Parsing

extension HTTPRequest {
    /// Parses an HTTP request from raw data.
    /// - Parameters:
    ///   - data: Raw HTTP request data
    ///   - baseURL: Base URL for relative requests
    /// - Returns: Parsed request, or nil if invalid
    public static func parse(from data: Data, baseURL: URL? = nil) -> HTTPRequest? {
        guard let string = String(data: data, encoding: .utf8) else { return nil }
        return parse(from: string, baseURL: baseURL)
    }

    /// Parses an HTTP request from a string.
    /// - Parameters:
    ///   - string: Raw HTTP request string
    ///   - baseURL: Base URL for relative requests
    /// - Returns: Parsed request, or nil if invalid
    public static func parse(from string: String, baseURL: URL? = nil) -> HTTPRequest? {
        let lines = string.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }

        // Parse request line
        let requestLine = lines[0].components(separatedBy: " ")
        guard requestLine.count >= 2 else { return nil }

        let method = requestLine[0]
        let path = requestLine[1]
        let httpVersion = requestLine.count >= 3 ? requestLine[2] : "HTTP/1.1"

        // Determine URL
        let url: URL?
        if path.hasPrefix("http://") || path.hasPrefix("https://") {
            url = URL(string: path)
        } else if let base = baseURL {
            url = URL(string: path, relativeTo: base)
        } else {
            url = URL(string: "http://localhost\(path)")
        }

        guard let finalURL = url else { return nil }

        // Parse headers
        var headers = HTTPHeaders()
        var bodyStart = 0

        for i in 1..<lines.count {
            let line = lines[i]
            if line.isEmpty {
                bodyStart = i + 1
                break
            }
            if let colonIndex = line.firstIndex(of: ":") {
                let name = String(line[..<colonIndex])
                let valueStart = line.index(after: colonIndex)
                let value = String(line[valueStart...]).trimmingCharacters(in: .whitespaces)
                headers.add(name, value: value)
            }
        }

        // Parse body
        var body: Data? = nil
        if bodyStart > 0 && bodyStart < lines.count {
            let bodyLines = lines[bodyStart...].joined(separator: "\r\n")
            body = bodyLines.data(using: .utf8)
        }

        return HTTPRequest(
            method: method,
            url: finalURL,
            httpVersion: httpVersion,
            headers: headers,
            body: body
        )
    }
}
