import Foundation

// MARK: - Default Reasons

extension HTTPResponse {

    /// Gets the default reason phrase for a status code.
    public static func defaultReason(for statusCode: Int) -> String {
        switch statusCode {
        // 1xx Informational
        case 100: return "Continue"
        case 101: return "Switching Protocols"
        case 102: return "Processing"
        case 103: return "Early Hints"

        // 2xx Success
        case 200: return "OK"
        case 201: return "Created"
        case 202: return "Accepted"
        case 203: return "Non-Authoritative Information"
        case 204: return "No Content"
        case 205: return "Reset Content"
        case 206: return "Partial Content"
        case 207: return "Multi-Status"
        case 208: return "Already Reported"
        case 226: return "IM Used"

        // 3xx Redirection
        case 300: return "Multiple Choices"
        case 301: return "Moved Permanently"
        case 302: return "Found"
        case 303: return "See Other"
        case 304: return "Not Modified"
        case 305: return "Use Proxy"
        case 307: return "Temporary Redirect"
        case 308: return "Permanent Redirect"

        // 4xx Client Errors
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 402: return "Payment Required"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 405: return "Method Not Allowed"
        case 406: return "Not Acceptable"
        case 407: return "Proxy Authentication Required"
        case 408: return "Request Timeout"
        case 409: return "Conflict"
        case 410: return "Gone"
        case 411: return "Length Required"
        case 412: return "Precondition Failed"
        case 413: return "Payload Too Large"
        case 414: return "URI Too Long"
        case 415: return "Unsupported Media Type"
        case 416: return "Range Not Satisfiable"
        case 417: return "Expectation Failed"
        case 418: return "I'm a teapot"
        case 421: return "Misdirected Request"
        case 422: return "Unprocessable Entity"
        case 423: return "Locked"
        case 424: return "Failed Dependency"
        case 425: return "Too Early"
        case 426: return "Upgrade Required"
        case 428: return "Precondition Required"
        case 429: return "Too Many Requests"
        case 431: return "Request Header Fields Too Large"
        case 451: return "Unavailable For Legal Reasons"

        // 5xx Server Errors
        case 500: return "Internal Server Error"
        case 501: return "Not Implemented"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        case 504: return "Gateway Timeout"
        case 505: return "HTTP Version Not Supported"
        case 506: return "Variant Also Negotiates"
        case 507: return "Insufficient Storage"
        case 508: return "Loop Detected"
        case 510: return "Not Extended"
        case 511: return "Network Authentication Required"

        default: return "Unknown"
        }
    }
}

// MARK: - Status Code Categories

extension HTTPResponse {
    /// HTTP status code categories.
    public enum StatusCategory: Sendable {
        case informational  // 1xx
        case success        // 2xx
        case redirection    // 3xx
        case clientError    // 4xx
        case serverError    // 5xx
        case unknown

        public init(statusCode: Int) {
            switch statusCode {
            case 100..<200: self = .informational
            case 200..<300: self = .success
            case 300..<400: self = .redirection
            case 400..<500: self = .clientError
            case 500..<600: self = .serverError
            default: self = .unknown
            }
        }
    }

    /// The status code category.
    public var statusCategory: StatusCategory {
        StatusCategory(statusCode: statusCode)
    }
}

// MARK: - Parsing

extension HTTPResponse {
    /// Parses an HTTP response from raw data.
    /// - Parameter data: Raw HTTP response data
    /// - Returns: Parsed response, or nil if invalid
    public static func parse(from data: Data) -> HTTPResponse? {
        guard let string = String(data: data, encoding: .utf8) else { return nil }
        return parse(from: string)
    }

    /// Parses an HTTP response from a string.
    /// - Parameter string: Raw HTTP response string
    /// - Returns: Parsed response, or nil if invalid
    public static func parse(from string: String) -> HTTPResponse? {
        let lines = string.components(separatedBy: "\r\n")
        guard !lines.isEmpty else { return nil }

        // Parse status line
        let statusLine = lines[0]
        let parts = statusLine.components(separatedBy: " ")
        guard parts.count >= 2 else { return nil }

        let httpVersion = parts[0]
        guard let statusCode = Int(parts[1]) else { return nil }
        let reason = parts.count >= 3 ? parts[2...].joined(separator: " ") : nil

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

        return HTTPResponse(
            statusCode: statusCode,
            reason: reason,
            httpVersion: httpVersion,
            headers: headers,
            body: body
        )
    }
}
