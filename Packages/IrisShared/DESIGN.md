# IrisShared — Extension Management & Shared Services

## What This Does
Manages the lifecycle of all 4 system extensions (install, uninstall, status
checking, clean reinstall) and provides shared types used across the app's
packages: error types, extension state machines, and network filter/DNS proxy
configuration helpers.

## Why This Design
System extensions have complex lifecycle requirements — they need user
approval, can fail with obscure error codes, and require NE framework
configuration after activation. Centralizing this in one package keeps every
UI module from reimplementing the same approval/polling/error-handling logic.

XPC protocols themselves live in `Shared/` (not here) because extensions
can't import packages. This package handles the app-side management only.

## Data Flow
```
App → ExtensionManager.installExtension(.network)
  → OSSystemExtensionManager.submitRequest()
  → delegate callbacks: needsApproval / completed / failed
  → update @Published state
  → on success: NetworkFilterManager.enableFilter() / DNSProxyManager.enable()
  → fire onNetworkExtensionReady callback → stores connect via XPC
```

## Decisions Made
- **ExtensionManager as singleton** — there's exactly one system extension
  manager per app process. Injection still possible via init for testing.
- **Polling for approval** — no delegate callback when user clicks "Allow"
  in System Settings. Timer polls NEFilterManager every 2s until installed.
- **XPC ping for status** — endpoint and proxy extensions have no NE manager
  equivalent. Status checked by attempting XPC connection with 0.5s timeout.
- **Sequential clean reinstall** — uninstall network → endpoint → clean NE
  config → reinstall all 4 in sequence. Parallel would race on delegate.
- **4 extension types** — network, endpoint, proxy, dns. Each independently
  installable and stateful.

## Key Files
- `Services/ExtensionManager.swift` — Core class, published state, callbacks
- `Services/ExtensionManager+Installation.swift` — Install, uninstall, reinstall
- `Services/ExtensionManager+StatusChecking.swift` — Status checks, XPC ping, polling
- `Services/ExtensionManager+Delegate.swift` — OSSystemExtensionRequestDelegate
- `Services/ExtensionManager+Filter.swift` — NE filter, DNS proxy, FDA, settings
- `Services/ExtensionTypes.swift` — ExtensionType, ExtensionState, FilterState enums
- `Services/NetworkFilterManager.swift` — NEFilterManager configuration
- `Services/DNSProxyManager.swift` — NEDNSProxyManager configuration
- `Errors/IrisError.swift` — Shared error types
