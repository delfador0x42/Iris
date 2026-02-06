import Foundation

/// Unified byte formatting utility for consistent display across the app
public enum ByteFormatter {

    /// Formatting style for byte values
    public enum Style {
        /// Abbreviated format: "1.1K", "2.3M", "500B" (compact UI)
        case abbreviated
        /// Full format: "1.1 KB", "2.3 MB", "500 bytes" (detailed views)
        case full
    }

    /// Format bytes as human-readable string
    /// - Parameters:
    ///   - bytes: The byte count to format
    ///   - style: The formatting style to use
    /// - Returns: Formatted string representation
    public static func format(_ bytes: UInt64, style: Style = .full) -> String {
        switch style {
        case .abbreviated:
            return formatAbbreviated(bytes)
        case .full:
            return formatFull(bytes)
        }
    }

    // MARK: - Private Methods

    /// Abbreviated format: "1.1K", "2.3M", "500B"
    private static func formatAbbreviated(_ bytes: UInt64) -> String {
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

    /// Full format: "1.1 KB", "2.3 MB", "500 bytes"
    private static func formatFull(_ bytes: UInt64) -> String {
        let units = ["bytes", "KB", "MB", "GB", "TB"]
        var value = Double(bytes)
        var unitIndex = 0

        while value >= 1024 && unitIndex < units.count - 1 {
            value /= 1024
            unitIndex += 1
        }

        if unitIndex == 0 {
            return "\(bytes) bytes"
        } else {
            return String(format: "%.1f %@", value, units[unitIndex])
        }
    }
}
