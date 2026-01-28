import Foundation

/// Format bytes to human-readable string (matching dust's format)
func formatSize(_ bytes: UInt64) -> String {
    let units: [(String, UInt64)] = [
        ("P", 1024 * 1024 * 1024 * 1024 * 1024),
        ("T", 1024 * 1024 * 1024 * 1024),
        ("G", 1024 * 1024 * 1024),
        ("M", 1024 * 1024),
        ("K", 1024)
    ]

    for (suffix, threshold) in units {
        if bytes >= threshold {
            let value = Double(bytes) / Double(threshold)
            if value < 10 {
                return String(format: "%.1f%@", value, suffix)
            } else {
                return String(format: "%.0f%@", value, suffix)
            }
        }
    }

    return "\(bytes)B"
}
