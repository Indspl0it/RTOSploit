# Changelog

## [0.2.0] — 2026-02-27

### Added

- **SARIF + HTML Reporting** — `Finding` and `EngagementReport` data models with converters from crash, exploit, and CVE sources. `SARIFGenerator` produces SARIF 2.1.0 JSON for GitHub Security tab. `HTMLGenerator` produces self-contained offline-viewable HTML reports with severity badges, sortable tables, and collapsible details. New `rtosploit report generate` CLI command.
- **Crash Triage Pipeline** — `ExploitabilityClassifier` with MSEC-style classification via ARM CFSR register analysis (IACCVIOL, MSTKERR, UNDEFINSTR, etc.). `CrashMinimizer` with binary-search input reduction. `TriagePipeline` orchestrator. New `rtosploit triage` CLI command.
- **CVE Correlation** — `CVEDatabase` with 47 bundled FreeRTOS/ThreadX/Zephyr CVEs. `CVECorrelator` with version-range matching against firmware fingerprint. `NVDClient` for NVD 2.0 API updates. New `rtosploit cve scan|search|update` CLI commands.
- **Coverage Visualization** — `BitmapReader` for AFL-style 64KB bitmaps. `CoverageMapper` for trace logs and bitmap-to-address mapping via Capstone disassembly. `CoverageVisualizer` with Rich terminal heatmaps and HTML output. New `rtosploit coverage view|stats` CLI commands.
- **CI/CD Pipeline Mode** — `CIPipeline` orchestrator: fingerprint → CVE → fuzz → triage → report. `CIConfig` with severity gate (`--fail-on`). Exit codes: 0=clean, 1=findings, 2=error. New `rtosploit scan` CLI command.
- **E2E Integration Tests** — 15 end-to-end tests that boot real firmware in QEMU, read registers via GDB RSP, inject faults, run exploits, triage crashes, and generate reports through the full v2 pipeline.

### Changed

- `run_exploit()` now propagates CVE ID from module metadata even when `check()` returns not_vulnerable.
- `ExploitRegistry` now supports `get_modules_for_cve(cve_id)` to cross-reference CVEs with available exploit modules.

### Test Summary

- 753 Python tests passing (119 new v2 tests)
- 15 QEMU integration tests passing
- All Rust crate tests passing

## [0.1.0] — 2026-02-27

### Added

- Phase 1: Project foundation (Python package, Rust workspace, config)
- Phase 2: Core utilities (FirmwareImage, MemoryMap, disassembly, error handling)
- Phase 3: QEMU emulation engine (QEMUInstance, QMPClient, GDBClient, SnapshotManager)
- Phase 4: SVD Rust crate (parser, stub generator)
- Phase 5: LibAFL fuzzer core (mutations, coverage bitmap, MMIO-aware splitting)
- Phase 5B: Instrumentation bus (13 event types, telemetry, trace writer)
- Phase 6: Crash detection (6-layer: HardFault, watchdog, canary, heap shadow)
- Phase 7: Firmware analysis (RTOS fingerprint, heap detect, MPU check, strings)
- Phase 8: Exploit framework (ExploitModule ABC, ExploitRegistry, ExploitTarget, runner)
- Phase 9: FreeRTOS exploit modules (6 modules, CVE-2021-43997, CVE-2024-28115)
- Phase 10: ThreadX exploit modules (KOM, byte pool, thread entry)
- Phase 11: Zephyr exploit modules (syscall race, BLE overflow, 3 CVE stubs)
- Phase 12+13: Payload generator (ARM Thumb2/RISC-V shellcode, ROP chains, encoders)
- Phase 14: VulnRange CVE lab (5 ranges: FreeRTOS DNS/MPU/ROP/LLMNR, ThreadX KOM)
- Phase 15: CLI interface (7 command groups: emulate/fuzz/exploit/payload/analyze/svd/vulnrange)
- Phase 16: Interactive console (Metasploit-style REPL with prompt_toolkit)

### Security Note

This framework is for authorized security research, CTF challenges, and educational use only.
