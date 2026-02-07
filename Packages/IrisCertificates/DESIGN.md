# IrisCertificates — CA & Certificate Management

## What This Does
Generates and manages a self-signed CA certificate for HTTPS MITM
interception. Creates per-domain server certificates on demand, caches them,
and stores the CA in the macOS Keychain.

## Why This Design
TLS MITM requires presenting a trusted certificate to the client for every
intercepted domain. A local CA cert (trusted by the user) signs per-domain
certs on the fly. Apple's Security framework handles all crypto — no OpenSSL
dependency. Keychain storage means the CA persists across app launches and
the user can manage trust via Keychain Access.

## Data Flow
```
App launch → CertificateStore.loadOrCreateCA()
  → KeychainManager.loadCACertificate()
  → if exists: load CA cert + private key from Keychain
  → if not: CertificateGenerator.generateCA()
    → create self-signed X.509 CA cert (ASN.1 DER)
    → store in Keychain via KeychainManager

TLS handshake (in proxy extension):
  → extract SNI from ClientHello
  → CertificateCache.get(sni)
  → if miss: CertificateGenerator.generateServerCert(for: sni)
    → sign with CA private key
    → store in CertificateCache (max 1000)
  → return cert to TLSSession for client handshake
```

## Decisions Made
- **Security framework, not OpenSSL** — Apple's SecKey, SecCertificate, and
  SecIdentity APIs handle RSA key generation, X.509 construction, and
  Keychain storage. Zero third-party crypto dependencies.
- **ASN.1 DER encoding by hand** — CertificateGenerator+ASN1.swift builds
  DER-encoded certificates from scratch. More control than trying to use
  higher-level APIs that don't expose all X.509 fields.
- **In-memory certificate cache** — 1000-entry LRU cache avoids regenerating
  certs for frequently visited domains. Cache is per-process (extension).
- **Keychain for CA persistence** — CA cert and private key stored in the
  app's Keychain access group. User can delete or distrust via Keychain
  Access.app.

## Key Files
- `CertificateStore.swift` — Published state: isCAInstalled, isCATrusted
- `CertificateGenerator.swift` — CA generation, server cert signing
- `CertificateGenerator+ASN1.swift` — DER encoding helpers
- `CertificateGenerator+Components.swift` — X.509 field builders
- `KeychainManager.swift` — Keychain CRUD for certs and keys
- `KeychainManager+Certificate.swift` — SecCertificate operations
- `KeychainManager+PrivateKey.swift` — SecKey operations
- `CertificateCache.swift` — In-memory SNI → cert cache
- `CertificateError.swift` — Error types
