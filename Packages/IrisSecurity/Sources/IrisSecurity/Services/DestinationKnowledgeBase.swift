import Foundation

// MARK: - Known network destination database

extension ProcessKnowledgeBase {

    // swiftlint:disable:next function_body_length
    static let knownDestinations: [DestinationInfo] = {
        typealias D = DestinationInfo; typealias C = DestinationCategory
        return [
            // Apple services
            D(pattern: "*.apple.com", owner: "Apple", purpose: "Apple services (iCloud, App Store, updates)", category: .appleService, isTelemetry: false, isEssential: true),
            D(pattern: "*.icloud.com", owner: "Apple", purpose: "iCloud sync, Drive, Photos, Keychain", category: .appleService, isTelemetry: false, isEssential: true),
            D(pattern: "*.icloud-content.com", owner: "Apple", purpose: "iCloud content delivery", category: .cdn, isTelemetry: false, isEssential: false),
            D(pattern: "*.mzstatic.com", owner: "Apple", purpose: "App Store and iTunes content", category: .cdn, isTelemetry: false, isEssential: true),
            D(pattern: "*.apple-cloudkit.com", owner: "Apple", purpose: "CloudKit push and sync", category: .appleService, isTelemetry: false, isEssential: true),
            D(pattern: "*.cdn-apple.com", owner: "Apple", purpose: "Apple CDN for downloads", category: .cdn, isTelemetry: false, isEssential: false),
            D(pattern: "*.push.apple.com", owner: "Apple", purpose: "APNs push notifications", category: .appleService, isTelemetry: false, isEssential: true),
            D(pattern: "ocsp.apple.com", owner: "Apple", purpose: "Certificate revocation (OCSP)", category: .securityService, isTelemetry: false, isEssential: true),
            D(pattern: "crl.apple.com", owner: "Apple", purpose: "Certificate revocation lists", category: .securityService, isTelemetry: false, isEssential: true),
            D(pattern: "time.apple.com", owner: "Apple", purpose: "NTP time sync", category: .appleService, isTelemetry: false, isEssential: true),
            D(pattern: "gs-loc.apple.com", owner: "Apple", purpose: "WiFi positioning database", category: .appleService, isTelemetry: false, isEssential: false),
            D(pattern: "mesu.apple.com", owner: "Apple", purpose: "Software update catalog", category: .appleService, isTelemetry: false, isEssential: true),
            D(pattern: "xp.apple.com", owner: "Apple", purpose: "XProtect malware signatures", category: .securityService, isTelemetry: false, isEssential: true),

            // Certificate authorities
            D(pattern: "ocsp.digicert.com", owner: "DigiCert", purpose: "Certificate revocation", category: .securityService, isTelemetry: false, isEssential: true),
            D(pattern: "ocsp.sectigo.com", owner: "Sectigo", purpose: "Certificate revocation", category: .securityService, isTelemetry: false, isEssential: true),
            D(pattern: "*.letsencrypt.org", owner: "Let's Encrypt", purpose: "Free TLS CA", category: .securityService, isTelemetry: false, isEssential: false),
            D(pattern: "crl.globalsign.com", owner: "GlobalSign", purpose: "Certificate revocation", category: .securityService, isTelemetry: false, isEssential: false),

            // CDNs
            D(pattern: "*.cloudfront.net", owner: "Amazon CloudFront", purpose: "CDN — many services", category: .cdn, isTelemetry: false, isEssential: false),
            D(pattern: "*.akamaiedge.net", owner: "Akamai", purpose: "CDN", category: .cdn, isTelemetry: false, isEssential: false),
            D(pattern: "*.akamaitechnologies.com", owner: "Akamai", purpose: "CDN", category: .cdn, isTelemetry: false, isEssential: false),
            D(pattern: "*.fastly.net", owner: "Fastly", purpose: "CDN", category: .cdn, isTelemetry: false, isEssential: false),
            D(pattern: "*.cloudflare.com", owner: "Cloudflare", purpose: "CDN and DDoS protection", category: .cdn, isTelemetry: false, isEssential: false),

            // Cloud providers
            D(pattern: "*.amazonaws.com", owner: "AWS", purpose: "Cloud services", category: .cloudProvider, isTelemetry: false, isEssential: false),
            D(pattern: "*.azure.com", owner: "Microsoft", purpose: "Azure cloud", category: .cloudProvider, isTelemetry: false, isEssential: false),
            D(pattern: "*.microsoft.com", owner: "Microsoft", purpose: "Microsoft services", category: .cloudProvider, isTelemetry: false, isEssential: false),
            D(pattern: "*.google.com", owner: "Google", purpose: "Google services", category: .cloudProvider, isTelemetry: false, isEssential: false),
            D(pattern: "*.googleapis.com", owner: "Google", purpose: "Google APIs", category: .cloudProvider, isTelemetry: false, isEssential: false),
            D(pattern: "*.gstatic.com", owner: "Google", purpose: "Static content", category: .cdn, isTelemetry: false, isEssential: false),
            D(pattern: "*.firebaseio.com", owner: "Google Firebase", purpose: "Firebase services", category: .cloudProvider, isTelemetry: false, isEssential: false),

            // Analytics / Telemetry
            D(pattern: "*.google-analytics.com", owner: "Google", purpose: "Usage tracking", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.doubleclick.net", owner: "Google", purpose: "Ad tracking", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.crashlytics.com", owner: "Google", purpose: "Crash reporting", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.segment.io", owner: "Twilio", purpose: "Analytics pipeline", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.segment.com", owner: "Twilio", purpose: "Analytics pipeline", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.mixpanel.com", owner: "Mixpanel", purpose: "Product analytics", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.amplitude.com", owner: "Amplitude", purpose: "Product analytics", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.sentry.io", owner: "Sentry", purpose: "Error tracking", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.datadoghq.com", owner: "Datadog", purpose: "Infrastructure monitoring", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.newrelic.com", owner: "New Relic", purpose: "APM monitoring", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.hotjar.com", owner: "Hotjar", purpose: "Session recording", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.facebook.com", owner: "Meta", purpose: "Facebook services", category: .analytics, isTelemetry: true, isEssential: false),
            D(pattern: "*.fbcdn.net", owner: "Meta", purpose: "Facebook CDN", category: .cdn, isTelemetry: true, isEssential: false),

            // Developer services
            D(pattern: "*.github.com", owner: "GitHub", purpose: "Code hosting", category: .developerService, isTelemetry: false, isEssential: false),
            D(pattern: "*.githubusercontent.com", owner: "GitHub", purpose: "Raw content", category: .developerService, isTelemetry: false, isEssential: false),
            D(pattern: "*.gitlab.com", owner: "GitLab", purpose: "Code hosting", category: .developerService, isTelemetry: false, isEssential: false),
            D(pattern: "registry.npmjs.org", owner: "npm", purpose: "Node package registry", category: .developerService, isTelemetry: false, isEssential: false),
            D(pattern: "*.pypi.org", owner: "PSF", purpose: "Python packages", category: .developerService, isTelemetry: false, isEssential: false),
            D(pattern: "crates.io", owner: "Rust Foundation", purpose: "Rust packages", category: .developerService, isTelemetry: false, isEssential: false),
            D(pattern: "static.rust-lang.org", owner: "Rust Foundation", purpose: "Rust toolchain", category: .developerService, isTelemetry: false, isEssential: false),
            D(pattern: "*.docker.io", owner: "Docker", purpose: "Container images", category: .developerService, isTelemetry: false, isEssential: false),
            D(pattern: "marketplace.visualstudio.com", owner: "Microsoft", purpose: "VS Code extensions", category: .developerService, isTelemetry: false, isEssential: false),

            // DNS providers
            D(pattern: "dns.google", owner: "Google", purpose: "Public DNS (DoH)", category: .dns, isTelemetry: false, isEssential: true),
            D(pattern: "dns.cloudflare.com", owner: "Cloudflare", purpose: "DNS (DoH)", category: .dns, isTelemetry: false, isEssential: true),
            D(pattern: "dns.quad9.net", owner: "Quad9", purpose: "Security DNS", category: .dns, isTelemetry: false, isEssential: true),

            // Security services
            D(pattern: "*.virustotal.com", owner: "Google", purpose: "Malware scanning", category: .securityService, isTelemetry: false, isEssential: false),
            D(pattern: "*.abuseipdb.com", owner: "AbuseIPDB", purpose: "IP abuse reports", category: .securityService, isTelemetry: false, isEssential: false),
            D(pattern: "api.greynoise.io", owner: "GreyNoise", purpose: "Scanner identification", category: .securityService, isTelemetry: false, isEssential: false),
        ]
    }()
}
