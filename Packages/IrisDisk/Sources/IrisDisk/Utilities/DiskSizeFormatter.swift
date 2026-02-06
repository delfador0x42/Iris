import Foundation

/// Format bytes to human-readable string (matching dust's format)
/// Uses ByteFormatter with abbreviated style for compact display
func formatSize(_ bytes: UInt64) -> String {
    ByteFormatter.format(bytes, style: .abbreviated)
}
