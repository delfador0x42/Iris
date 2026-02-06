//
//  CertificateGeneratorTests.swift
//  IrisCertificatesTests
//
//  Tests for certificate generation functionality.
//

import Testing
import Foundation
import Security

@Suite("CertificateGenerator Tests")
struct CertificateGeneratorTests {

    @Test("CA generation creates valid key pair and certificate")
    @MainActor
    func testCAGeneration() async throws {
        let generator = CertificateGenerator()

        let (privateKey, certificate) = try generator.createCA()

        // Verify we got a valid private key
        #expect(privateKey != nil)

        // Verify we can extract the public key
        let publicKey = SecKeyCopyPublicKey(privateKey)
        #expect(publicKey != nil)

        // Verify certificate is valid
        #expect(certificate != nil)

        // Verify certificate subject contains expected values
        if let summary = SecCertificateCopySubjectSummary(certificate) as String? {
            #expect(summary.contains("Iris") || summary.contains("CA"))
        }
    }

    @Test("CA generation with custom key size")
    @MainActor
    func testCAGenerationCustomKeySize() async throws {
        let generator = CertificateGenerator()

        // Test with 4096-bit key
        let (privateKey, certificate) = try generator.createCA(keySize: 4096)

        #expect(privateKey != nil)
        #expect(certificate != nil)

        // Verify key attributes
        if let attributes = SecKeyCopyAttributes(privateKey) as? [String: Any] {
            if let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int {
                #expect(keySize == 4096)
            }
        }
    }

    @Test("Leaf certificate generation for hostname")
    @MainActor
    func testLeafCertificateGeneration() async throws {
        let generator = CertificateGenerator()

        // First create a CA
        let (caPrivateKey, caCertificate) = try generator.createCA()

        // Generate a leaf certificate for a hostname
        let hostname = "example.com"
        let (leafPrivateKey, leafCertificate) = try generator.createLeafCertificate(
            for: hostname,
            caPrivateKey: caPrivateKey,
            caCertificate: caCertificate
        )

        #expect(leafPrivateKey != nil)
        #expect(leafCertificate != nil)

        // Verify the certificate contains the hostname
        if let summary = SecCertificateCopySubjectSummary(leafCertificate) as String? {
            #expect(summary.contains(hostname))
        }
    }

    @Test("Leaf certificate for wildcard domain")
    @MainActor
    func testWildcardLeafCertificate() async throws {
        let generator = CertificateGenerator()

        let (caPrivateKey, caCertificate) = try generator.createCA()

        let hostname = "*.example.com"
        let (leafPrivateKey, leafCertificate) = try generator.createLeafCertificate(
            for: hostname,
            caPrivateKey: caPrivateKey,
            caCertificate: caCertificate
        )

        #expect(leafPrivateKey != nil)
        #expect(leafCertificate != nil)
    }

    @Test("Multiple leaf certificates can be generated from same CA")
    @MainActor
    func testMultipleLeafCertificates() async throws {
        let generator = CertificateGenerator()

        let (caPrivateKey, caCertificate) = try generator.createCA()

        let hostnames = ["example.com", "api.example.com", "test.local"]
        var certificates: [SecCertificate] = []

        for hostname in hostnames {
            let (_, leafCert) = try generator.createLeafCertificate(
                for: hostname,
                caPrivateKey: caPrivateKey,
                caCertificate: caCertificate
            )
            certificates.append(leafCert)
        }

        #expect(certificates.count == 3)

        // Verify each certificate is unique
        let certDataSet = Set(certificates.map { SecCertificateCopyData($0) as Data })
        #expect(certDataSet.count == 3)
    }
}

@Suite("CertificateCache Tests")
struct CertificateCacheTests {

    @Test("Empty cache returns nil")
    @MainActor
    func testEmptyCache() async {
        let cache = CertificateCache(maxCapacity: 10)

        let result = cache.get(hostname: "example.com")
        #expect(result == nil)
        #expect(cache.count == 0)
    }

    @Test("Cache stores and retrieves certificates")
    @MainActor
    func testCacheSetAndGet() async throws {
        let cache = CertificateCache(maxCapacity: 10)
        let generator = CertificateGenerator()

        let (caPrivateKey, caCertificate) = try generator.createCA()
        let (leafKey, leafCert) = try generator.createLeafCertificate(
            for: "example.com",
            caPrivateKey: caPrivateKey,
            caCertificate: caCertificate
        )

        cache.set(hostname: "example.com", certificate: (leafKey, leafCert))

        #expect(cache.count == 1)

        let result = cache.get(hostname: "example.com")
        #expect(result != nil)
        #expect(result?.certificate != nil)
        #expect(result?.privateKey != nil)
    }

    @Test("Cache respects capacity limit")
    @MainActor
    func testCacheCapacityLimit() async throws {
        let cache = CertificateCache(maxCapacity: 3)
        let generator = CertificateGenerator()

        let (caPrivateKey, caCertificate) = try generator.createCA()

        // Add 5 entries to a cache with capacity 3
        for i in 0..<5 {
            let (leafKey, leafCert) = try generator.createLeafCertificate(
                for: "host\(i).com",
                caPrivateKey: caPrivateKey,
                caCertificate: caCertificate
            )
            cache.set(hostname: "host\(i).com", certificate: (leafKey, leafCert))
        }

        // Cache should not exceed capacity
        #expect(cache.count <= 3)

        // Most recently added entries should be present
        #expect(cache.get(hostname: "host4.com") != nil)
        #expect(cache.get(hostname: "host3.com") != nil)
    }

    @Test("Cache clear removes all entries")
    @MainActor
    func testCacheClear() async throws {
        let cache = CertificateCache(maxCapacity: 10)
        let generator = CertificateGenerator()

        let (caPrivateKey, caCertificate) = try generator.createCA()

        for i in 0..<5 {
            let (leafKey, leafCert) = try generator.createLeafCertificate(
                for: "host\(i).com",
                caPrivateKey: caPrivateKey,
                caCertificate: caCertificate
            )
            cache.set(hostname: "host\(i).com", certificate: (leafKey, leafCert))
        }

        #expect(cache.count == 5)

        cache.clear()

        #expect(cache.count == 0)
        #expect(cache.get(hostname: "host0.com") == nil)
    }

    @Test("Cache removes specific hostname")
    @MainActor
    func testCacheRemove() async throws {
        let cache = CertificateCache(maxCapacity: 10)
        let generator = CertificateGenerator()

        let (caPrivateKey, caCertificate) = try generator.createCA()
        let (leafKey, leafCert) = try generator.createLeafCertificate(
            for: "example.com",
            caPrivateKey: caPrivateKey,
            caCertificate: caCertificate
        )

        cache.set(hostname: "example.com", certificate: (leafKey, leafCert))
        #expect(cache.count == 1)

        cache.remove(hostname: "example.com")
        #expect(cache.count == 0)
        #expect(cache.get(hostname: "example.com") == nil)
    }

    @Test("Cache statistics are accurate")
    @MainActor
    func testCacheStats() async throws {
        let cache = CertificateCache(maxCapacity: 100, ttl: 3600)
        let generator = CertificateGenerator()

        let (caPrivateKey, caCertificate) = try generator.createCA()

        for i in 0..<5 {
            let (leafKey, leafCert) = try generator.createLeafCertificate(
                for: "host\(i).com",
                caPrivateKey: caPrivateKey,
                caCertificate: caCertificate
            )
            cache.set(hostname: "host\(i).com", certificate: (leafKey, leafCert))
        }

        let stats = cache.getStats()

        #expect(stats.count == 5)
        #expect(stats.capacity == 100)
        #expect(stats.ttl == 3600)
        #expect(stats.utilization == 5.0)
    }

    @Test("Cache TTL expiration")
    @MainActor
    func testCacheTTLExpiration() async throws {
        // Create cache with very short TTL
        let cache = CertificateCache(maxCapacity: 10, ttl: 0.1) // 100ms TTL
        let generator = CertificateGenerator()

        let (caPrivateKey, caCertificate) = try generator.createCA()
        let (leafKey, leafCert) = try generator.createLeafCertificate(
            for: "example.com",
            caPrivateKey: caPrivateKey,
            caCertificate: caCertificate
        )

        cache.set(hostname: "example.com", certificate: (leafKey, leafCert))

        // Should be available immediately
        #expect(cache.get(hostname: "example.com") != nil)

        // Wait for expiration
        try await Task.sleep(for: .milliseconds(150))

        // Should be expired now
        #expect(cache.get(hostname: "example.com") == nil)
    }
}
