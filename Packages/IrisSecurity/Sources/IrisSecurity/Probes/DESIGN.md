# Contradiction Probe Engine

## What This Does
Forces the system to reveal truth through action, not reporting.
Every probe compares 2+ independent sources of the same fact.
If they disagree, something is lying. The lie IS the detection.

## Why This Design
Standard EDR asks the OS "is this normal?" — but the OS is compromised.
Contradiction engines don't trust ANY single source. They triangulate.
A nation-state must defeat N independent observation methods simultaneously.
Each additional source raises adversary cost multiplicatively.

## Data Flow
1. ProbeRunner.runAll() → TaskGroup runs all probes in parallel
2. Each probe queries 2-4 independent sources, builds SourceComparisons
3. ProbeResult written to ~/.iris/probes/<probe-id>.json (Claude-readable)
4. Summary written to ~/.iris/probes/latest.json
5. toAnomalies() feeds existing SecurityAssessor scan pipeline
6. CLI: `iris-ctl probe` / `probeOne <id>` / `probeStatus`

## Decisions
- Protocol, not base class — probes are actors with different isolation needs
- 5-question metadata is mandatory — documentation IS the interface
- SourceComparison is the unit of work, not Anomaly — structure > description
- Backward compat via toAnomalies() — incremental migration, not big bang
- JSON to filesystem, not XPC — Claude reads files, not protocols

## Probes (9 active)
### Phase 1 — migrated from legacy scanners
- dyld-cache: disk UUID vs API vs mapped memory (3-way)
- sip-status: kernel config vs csr_check vs behavioral vs NVRAM (4-way)
- process-census: sysctl vs proc_listallpids vs processor_set_tasks (3-way)
- binary-integrity: disk __TEXT SHA256 vs memory __TEXT (per-binary)
- network-ghost: kernel sockets vs proxy attribution + orphan detection
### Phase 2 — new contradiction probes
- kext-census: KextManagerCopyLoadedKextInfo vs IOService plane vs IOKit diagnostics (3-way)
- dns-contradiction: system resolver vs direct UDP 8.8.8.8 vs DoH Cloudflare (3-way)
- timing-oracle: system clock vs 4 NTP servers (Apple, Google, Cloudflare, pool.ntp.org)
- trust-cache: static trust cache on Preboot volume vs runtime SecStaticCode cdhash (2-way)

## Temporal Comparison (Gap #1 — DONE)
ProbeDiff.diff(current, previous) detects state changes between runs.
Writes diff.json to ~/.iris/probes/. ProbeEngineView shows purple state-change banner.

## Gaps
1. ~~Temporal comparison~~ — DONE (ProbeDiff)
2. No probe-to-probe correlation (multiple contradictions = campaign)
3. Remaining 4 legacy probes not yet migrated
4. No firmware-level probes (SEP, ISP, ANE — may be impossible from userspace)
5. No probe result signing (attacker could tamper with JSON output)



