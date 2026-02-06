import SwiftUI

/// Badge showing HTTP method (GET, POST, etc.)
struct HTTPMethodBadge: View {
    let method: String

    var body: some View {
        Text(method)
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(methodColor)
            .cornerRadius(4)
    }

    private var methodColor: Color {
        switch method.uppercased() {
        case "GET":
            return .blue
        case "POST":
            return .orange
        case "PUT":
            return .purple
        case "PATCH":
            return .teal
        case "DELETE":
            return .red
        case "HEAD":
            return .gray
        case "OPTIONS":
            return .cyan
        case "CONNECT":
            return .indigo
        default:
            return .gray
        }
    }
}

/// Badge showing HTTP status code with color coding
struct HTTPStatusBadge: View {
    let statusCode: Int

    var body: some View {
        Text("\(statusCode)")
            .font(.system(size: 9, weight: .bold, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 5)
            .padding(.vertical, 2)
            .background(statusColor)
            .cornerRadius(4)
    }

    private var statusColor: Color {
        switch statusCode {
        case 200..<300:
            return .green
        case 300..<400:
            return .blue
        case 400..<500:
            return .orange
        case 500..<600:
            return .red
        default:
            return .gray
        }
    }
}

/// Badge showing threat classification (benign, malicious, unknown)
struct ThreatBadge: View {
    let classification: String

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: iconName)
                .font(.system(size: 9))
            Text(classification.capitalized)
                .font(.system(size: 9, weight: .bold))
        }
        .foregroundColor(.white)
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .background(badgeColor)
        .cornerRadius(4)
    }

    private var badgeColor: Color {
        switch classification.lowercased() {
        case "benign":
            return .green
        case "malicious":
            return .red
        case "unknown":
            return .gray
        default:
            return .gray
        }
    }

    private var iconName: String {
        switch classification.lowercased() {
        case "benign":
            return "checkmark.shield.fill"
        case "malicious":
            return "exclamationmark.shield.fill"
        case "unknown":
            return "questionmark.circle.fill"
        default:
            return "shield.fill"
        }
    }
}

#Preview("HTTP Badges") {
    VStack(spacing: 12) {
        HStack(spacing: 8) {
            HTTPMethodBadge(method: "GET")
            HTTPMethodBadge(method: "POST")
            HTTPMethodBadge(method: "PUT")
            HTTPMethodBadge(method: "DELETE")
            HTTPMethodBadge(method: "PATCH")
        }

        HStack(spacing: 8) {
            HTTPStatusBadge(statusCode: 200)
            HTTPStatusBadge(statusCode: 301)
            HTTPStatusBadge(statusCode: 404)
            HTTPStatusBadge(statusCode: 500)
        }
    }
    .padding()
    .background(Color.black)
}
