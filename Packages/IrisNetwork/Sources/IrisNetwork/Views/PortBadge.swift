import SwiftUI

/// Badge displaying a port number with color-coding based on service type
struct PortBadge: View {
    let port: UInt16
    @State private var isHovering = false

    var body: some View {
        Text("\(port)")
            .font(.system(size: 11, weight: .medium, design: .monospaced))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(portColor.opacity(isHovering ? 0.3 : 0.2))
            .foregroundColor(portColor)
            .cornerRadius(4)
            .onHover { isHovering = $0 }
            .help(portDescription)
    }

    private var portColor: Color {
        switch port {
        case 22: return .green         // SSH
        case 80, 8080: return .blue    // HTTP
        case 443, 8443: return .cyan   // HTTPS
        case 21: return .orange        // FTP
        case 23: return .red           // Telnet (insecure)
        case 25, 587: return .purple   // SMTP
        case 53: return .teal          // DNS
        case 3389: return .red         // RDP
        case 3306: return .yellow      // MySQL
        case 5432: return .blue        // PostgreSQL
        case 27017: return .green      // MongoDB
        case 6379: return .red         // Redis
        default: return .gray
        }
    }

    private var portDescription: String {
        switch port {
        case 21: return "FTP"
        case 22: return "SSH"
        case 23: return "Telnet"
        case 25: return "SMTP"
        case 53: return "DNS"
        case 80: return "HTTP"
        case 110: return "POP3"
        case 143: return "IMAP"
        case 443: return "HTTPS"
        case 587: return "SMTP (submission)"
        case 993: return "IMAPS"
        case 995: return "POP3S"
        case 3306: return "MySQL"
        case 3389: return "RDP"
        case 5432: return "PostgreSQL"
        case 5900: return "VNC"
        case 6379: return "Redis"
        case 8080: return "HTTP Alt"
        case 8443: return "HTTPS Alt"
        case 27017: return "MongoDB"
        default: return "Port \(port)"
        }
    }
}
