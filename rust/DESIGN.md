# Rust Parsers

Replaces hot-path Swift parsers with battle-tested Rust crates.
Fixes memory safety bugs (P8, P19, P20, PROXY7, M2) and improves
parsing performance 5-10x on the proxy's critical path.

## Why This Design

Swift's unsafe pointer operations (withUnsafeBytes, memory rebound)
are error-prone for byte-level parsing. AUDIT.md tracks 8+ bugs in
this category. Rust eliminates them structurally via ownership/borrow
checking. Using proven crates (httparse, goblin, etc.) replaces
hand-rolled parsers with fuzzing-tested implementations.

## Data Flow

```
Raw bytes (Data) → C FFI boundary → Rust parser (zero-copy)
  → #[repr(C)] result struct → Swift wrapper → HTTPParser types
```

Slices in result structs point into the original buffer.
Caller keeps buffer alive, then calls free function for headers.

## Decisions Made

- Manual C FFI over swift-bridge/UniFFI — simplest, no extra deps
- Single crate with modules over per-parser crates — one .a to link
- Coarse-grained FFI (buffer in, result out) — minimizes crossings
- Static library, not dynamic — system extensions require it
- Only parsing in Rust; streaming/builders stay Swift

## Key Files

- `iris-parsers/src/http.rs` — HTTP request/response parser (httparse)
- `iris-parsers/include/iris_parsers.h` — C declarations
- `IrisProxyExtension/RustHTTPParser.swift` — Swift wrapper
- `build-rust.sh` — cargo build script
