import Testing
import Foundation
@testable import IrisNetwork

@Suite("NetworkConnection Tests")
struct NetworkConnectionTests {

    // MARK: - Model Creation

    @Test("Connection initializes with all properties")
    func testConnectionInitialization() {
        let connection = createTestConnection()

        #expect(connection.processId == 1234)
        #expect(connection.processPath == "/usr/bin/curl")
        #expect(connection.processName == "curl")
        #expect(connection.localAddress == "192.168.1.100")
        #expect(connection.localPort == 54321)
        #expect(connection.remoteAddress == "93.184.216.34")
        #expect(connection.remotePort == 443)
        #expect(connection.protocol == .tcp)
        #expect(connection.state == .established)
    }

    // MARK: - Endpoint Formatting

    @Test("Local endpoint formats correctly")
    func testLocalEndpointFormat() {
        let connection = createTestConnection()
        #expect(connection.localEndpoint == "192.168.1.100:54321")
    }

    @Test("Remote endpoint formats with hostname when available")
    func testRemoteEndpointWithHostname() {
        let connection = createTestConnection(hostname: "example.com")
        #expect(connection.remoteEndpoint == "example.com:443")
    }

    @Test("Remote endpoint falls back to IP when no hostname")
    func testRemoteEndpointWithoutHostname() {
        let connection = createTestConnection(hostname: nil)
        #expect(connection.remoteEndpoint == "93.184.216.34:443")
    }

    @Test("Connection description shows full path")
    func testConnectionDescription() {
        let connection = createTestConnection()
        #expect(connection.connectionDescription == "192.168.1.100:54321 → 93.184.216.34:443")
    }

    // MARK: - Byte Tracking

    @Test("Total bytes sums up and down")
    func testTotalBytes() {
        var connection = createTestConnection()
        connection.bytesUp = 1024
        connection.bytesDown = 2048
        #expect(connection.totalBytes == 3072)
    }

    // MARK: - Byte Formatting

    @Test("Format bytes shows bytes for small values")
    func testFormatBytesSmall() {
        #expect(NetworkConnection.formatBytes(500) == "500 bytes")
    }

    @Test("Format bytes shows KB correctly")
    func testFormatBytesKB() {
        #expect(NetworkConnection.formatBytes(1024) == "1.0 KB")
        #expect(NetworkConnection.formatBytes(1536) == "1.5 KB")
    }

    @Test("Format bytes shows MB correctly")
    func testFormatBytesMB() {
        let oneMB: UInt64 = 1024 * 1024
        #expect(NetworkConnection.formatBytes(oneMB) == "1.0 MB")
    }

    @Test("Format bytes shows GB correctly")
    func testFormatBytesGB() {
        let oneGB: UInt64 = 1024 * 1024 * 1024
        #expect(NetworkConnection.formatBytes(oneGB) == "1.0 GB")
    }

    @Test("Formatted bytes up uses formatBytes")
    func testFormattedBytesUp() {
        var connection = createTestConnection()
        connection.bytesUp = 2048
        #expect(connection.formattedBytesUp == "2.0 KB")
    }

    @Test("Formatted bytes down uses formatBytes")
    func testFormattedBytesDown() {
        var connection = createTestConnection()
        connection.bytesDown = 3072
        #expect(connection.formattedBytesDown == "3.0 KB")
    }

    // MARK: - Protocol Types

    @Test("TCP protocol has correct raw value")
    func testTCPProtocol() {
        #expect(NetworkConnection.NetworkProtocol.tcp.rawValue == "TCP")
    }

    @Test("UDP protocol has correct raw value")
    func testUDPProtocol() {
        #expect(NetworkConnection.NetworkProtocol.udp.rawValue == "UDP")
    }

    // MARK: - Connection States

    @Test("Established state has correct raw value")
    func testEstablishedState() {
        #expect(NetworkConnection.ConnectionState.established.rawValue == "Established")
    }

    @Test("Listen state has correct raw value")
    func testListenState() {
        #expect(NetworkConnection.ConnectionState.listen.rawValue == "Listen")
    }

    @Test("Closed state has correct raw value")
    func testClosedState() {
        #expect(NetworkConnection.ConnectionState.closed.rawValue == "Closed")
    }

    // MARK: - Codable

    @Test("Connection encodes and decodes correctly")
    func testCodable() throws {
        let original = createTestConnection()
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let data = try encoder.encode(original)
        let decoded = try decoder.decode(NetworkConnection.self, from: data)

        #expect(decoded.id == original.id)
        #expect(decoded.processId == original.processId)
        #expect(decoded.remoteAddress == original.remoteAddress)
        #expect(decoded.protocol == original.protocol)
    }

    // MARK: - Helpers

    func createTestConnection(hostname: String? = nil) -> NetworkConnection {
        NetworkConnection(
            processId: 1234,
            processPath: "/usr/bin/curl",
            processName: "curl",
            localAddress: "192.168.1.100",
            localPort: 54321,
            remoteAddress: "93.184.216.34",
            remotePort: 443,
            remoteHostname: hostname,
            protocol: .tcp,
            state: .established
        )
    }
}
